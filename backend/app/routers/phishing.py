import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import ThreatAnalysis, SecurityEvent, AuditLog
from app.schemas import PhishingAnalysisRequest, PhishingAnalysisResponse
from app.services.phishing_engine import phishing_detector

router = APIRouter(prefix="/phishing", tags=["Phishing & Scam Detection"])

@router.post("/analyze", response_model=PhishingAnalysisResponse)
def analyze_phishing_submission(request: PhishingAnalysisRequest, db: Session = Depends(get_db)):
    sub_type = request.submission_type.lower()
    
    if sub_type == "url":
        result = phishing_detector.analyze_url(request.content)
    elif sub_type in ("email", "sms"):
        result = phishing_detector.analyze_message(
            content=request.content,
            submission_type=sub_type,
            email_subject=request.email_subject,
            sender_info=request.sender_info
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid submission type. Allowed: 'url', 'email', 'sms'.")

    # Persist analysis record
    threat_record = ThreatAnalysis(
        analysis_id=result.analysis_id,
        timestamp=result.timestamp,
        analysis_type=result.submission_type,
        target_input=result.target,
        risk_score=result.risk_score,
        risk_category=result.risk_category,
        detection_engine=result.detection_engine,
        indicators=json.dumps([ind.model_dump() for ind in result.indicators]),
        explanation=result.explanation,
        recommended_precautions=json.dumps(result.recommended_precautions),
        metadata_json=json.dumps(result.features_extracted)
    )
    db.add(threat_record)

    # If evaluated as Medium, High, or Critical, generate SecurityEvent in SOC stream
    if result.risk_score >= 35:
        event_obj = SecurityEvent(
            event_id=f"SEC-PHISH-{int(datetime.now(timezone.utc).timestamp()) % 100000}",
            timestamp=datetime.now(timezone.utc),
            event_source=f"User Submission / {sub_type.upper()} Analyzer",
            threat_category=f"Phishing / {result.risk_category} Risk",
            risk_score=result.risk_score,
            severity=result.risk_category,
            source_ip=None,
            dest_ip=None,
            domain=result.features_extracted.get("hostname") if sub_type == "url" else None,
            file_hash=None,
            user_account=request.sender_info,
            evidence=result.explanation,
            analysis_status="Analyzed",
            recommended_action=result.recommended_precautions[0] if result.recommended_precautions else "Monitor"
        )
        db.add(event_obj)

    # Log action in audit trail
    audit = AuditLog(
        action="PHISHING_ANALYSIS_RUN",
        actor="SOC Analyst / Portal User",
        resource_type="ThreatAnalysis",
        resource_id=result.analysis_id,
        details=f"Analyzed {sub_type} target '{result.target[:40]}'. Score: {result.risk_score}/100 ({result.risk_category})."
    )
    db.add(audit)
    db.commit()

    return result

@router.get("/samples")
def get_phishing_sample_scenarios():
    return [
        {
            "id": "url_m365_phish",
            "title": "Microsoft 365 Credential Harvest Portal",
            "submission_type": "url",
            "content": "http://login-microsoft365-verify.xyz/auth?session_token=99281a&redirect=office",
            "expected_risk": "Critical",
            "description": "Domain spoofing Microsoft 365 login on disposable .xyz TLD with plaintext HTTP."
        },
        {
            "id": "email_bec_wire",
            "title": "CEO Impersonation Wire Fraud (BEC)",
            "submission_type": "email",
            "email_subject": "URGENT & CONFIDENTIAL: Process Wire Transfer Immediately",
            "sender_info": "ceo-urgent-office@gmail-relay.com",
            "content": "Hi David, I am currently stuck in executive meetings and cannot take calls. Please process an urgent wire transfer of $48,500 to our contractor account before 4:00 PM today to prevent contract default. Send me the transfer confirmation receipt as soon as done.",
            "expected_risk": "Critical",
            "description": "Executive impersonation with coercive deadline and unauthorized fund disbursement directive."
        },
        {
            "id": "sms_bank_otp",
            "title": "Banking Security Alert SMS Phishing",
            "submission_type": "sms",
            "sender_info": "+1 (888) 555-0199",
            "content": "Chase Alert: A suspicious charge of $1,280.00 was attempted on your card. Click http://chase-security-verify.buzz/reset to restore banking access or call immediately.",
            "expected_risk": "High",
            "description": "Financial institution SMS phishing with shortened link to high-risk .buzz domain."
        },
        {
            "id": "email_benign_newsletter",
            "title": "Benign Corporate Weekly Engineering Digest",
            "submission_type": "email",
            "email_subject": "Weekly Engineering Team Digest & Architecture Review",
            "sender_info": "tech-leads@enterprise-corp.com",
            "content": "Hi team, please find attached the notes from yesterday's microservice architecture review. We will meet on Friday at 2:00 PM to finalize the database migration milestones. Let us know if you have any questions.",
            "expected_risk": "Low",
            "description": "Standard business internal correspondence without urgent threats or suspicious links."
        }
    ]
