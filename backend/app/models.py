from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(64), index=True, nullable=False)  # Super Admin, Security Administrator, SOC Analyst, Employee
    is_active = Column(Boolean, default=True, nullable=False)
    employee_id = Column(String(64), nullable=True, index=True)
    department = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_login = Column(DateTime, nullable=True)


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    company_email = Column(String(255), unique=True, index=True, nullable=False)
    phone_number = Column(String(64), nullable=True)
    department = Column(String(128), index=True, nullable=False)
    role_title = Column(String(128), nullable=False)
    monitoring_policy = Column(String(128), index=True, nullable=False) # Standard Workstation, Executive High-Risk, DevOps & Cloud Admin, Contractor Strict
    is_active = Column(Boolean, default=True, index=True, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)  # Dynamically updated based on active incidents
    created_at = Column(DateTime, default=utc_now, index=True, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class MonitoringSource(Base):
    __tablename__ = "monitoring_sources"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    source_type = Column(String(64), index=True, nullable=False)  # Email Gateway, Endpoint EDR, Corporate DNS, Perimeter Firewall, Zeek Sensor, Identity Provider, Cloud Audit Logs
    status = Column(String(32), default="ACTIVE", index=True, nullable=False)  # ACTIVE, DEGRADED, DISCONNECTED, SIMULATED
    events_ingested_count = Column(Integer, default=0, nullable=False)
    last_heartbeat = Column(DateTime, default=utc_now, nullable=False)
    is_simulated = Column(Boolean, default=True, nullable=False)
    configuration_json = Column(Text, nullable=True)


class SecretFinding(Base):
    """
    Data Loss Prevention (DLP) & Company Secret Detection Findings.
    Secrets are always masked in the UI and raw secrets are never persisted in plaintext.
    """
    __tablename__ = "secret_findings"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(64), unique=True, index=True, nullable=False)
    secret_type = Column(String(64), index=True, nullable=False)  # AWS Access Key, GitHub Token, Stripe Secret Key, RSA Private Key, Database URI, Slack Webhook, High-Entropy Secret
    masked_value = Column(String(128), nullable=False)  # e.g. AKIA****************5K2A
    secret_hash = Column(String(128), nullable=False, index=True)  # SHA-256 of raw secret to identify duplicate exposures
    source_location = Column(String(255), nullable=False)  # Email body, Git push diff, Chat log, CloudWatch log
    employee_id = Column(String(64), nullable=True, index=True)
    employee_email = Column(String(255), nullable=True, index=True)
    severity = Column(String(16), index=True, nullable=False)  # Critical, High, Medium, Low
    risk_score = Column(Integer, default=85, nullable=False)
    status = Column(String(32), default="NEW", index=True, nullable=False)  # NEW, REVOKED, CONTAINED, FALSE_POSITIVE
    recommendations = Column(Text, nullable=False)
    detected_at = Column(DateTime, default=utc_now, index=True, nullable=False)


class NotificationDelivery(Base):
    """
    Automated Alerts & Delivery tracking.
    Never includes raw secrets or passwords in payload.
    """
    __tablename__ = "notification_deliveries"

    id = Column(Integer, primary_key=True, index=True)
    delivery_id = Column(String(64), unique=True, index=True, nullable=False)
    recipient_type = Column(String(32), index=True, nullable=False)  # SOC_ANALYST, EMPLOYEE, SECURITY_ADMIN
    recipient_address = Column(String(255), nullable=False)  # Email address or phone
    channel = Column(String(32), default="EMAIL", nullable=False)  # EMAIL, SMS, IN_APP
    severity = Column(String(16), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    body_preview = Column(Text, nullable=False)  # Masked sanitized summary
    delivery_status = Column(String(32), default="DELIVERED", index=True, nullable=False)  # DELIVERED, QUEUED, SUPPRESSED_DUPLICATE, FAILED
    retry_count = Column(Integer, default=0, nullable=False)
    incident_id = Column(String(64), nullable=True, index=True)
    event_id = Column(String(64), nullable=True, index=True)
    dedup_key = Column(String(128), nullable=True, index=True)
    sent_at = Column(DateTime, default=utc_now, index=True, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)
    event_source = Column(String(64), index=True, nullable=False)  # e.g., "Email Gateway", "Zeek Sensor"
    threat_category = Column(String(64), index=True, nullable=False) # e.g., "Phishing", "Port Scan"
    risk_score = Column(Integer, nullable=False)  # 0 to 100
    severity = Column(String(16), index=True, nullable=False)  # Low, Medium, High, Critical
    
    # Contextual Network & System Indicators
    source_ip = Column(String(64), index=True, nullable=True)
    dest_ip = Column(String(64), index=True, nullable=True)
    domain = Column(String(255), index=True, nullable=True)
    file_hash = Column(String(128), index=True, nullable=True)
    user_account = Column(String(128), index=True, nullable=True)
    employee_id = Column(String(64), index=True, nullable=True)  # Associated employee
    
    evidence = Column(Text, nullable=False)  # JSON string or detailed evidence tokens
    raw_payload = Column(Text, nullable=True)
    analysis_status = Column(String(32), default="Analyzed", index=True)  # Pending, Analyzed, Correlated, Closed
    recommended_action = Column(Text, nullable=False)
    
    # Acknowledgment Tracking
    is_acknowledged = Column(Boolean, default=False, index=True, nullable=False)
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)

    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), nullable=True, index=True)
    incident = relationship("Incident", back_populates="events")

    __table_args__ = (
        Index("idx_sec_events_sev_time", "severity", "timestamp"),
        Index("idx_sec_events_src_dest", "source_ip", "dest_ip"),
    )


class ThreatAnalysis(Base):
    __tablename__ = "threat_analyses"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)
    analysis_type = Column(String(32), index=True, nullable=False)  # url, email, sms, file, network, secret
    target_input = Column(Text, nullable=False)  # url, file name, message snippet
    risk_score = Column(Integer, nullable=False)  # 0-100
    risk_category = Column(String(16), index=True, nullable=False)  # Low, Medium, High, Critical
    detection_engine = Column(String(64), nullable=False)  # e.g. "Heuristic + ML Classifier"
    
    indicators = Column(Text, nullable=False)  # JSON array of detected signals with scores
    explanation = Column(Text, nullable=False)
    recommended_precautions = Column(Text, nullable=False)  # JSON array
    metadata_json = Column(Text, nullable=True)  # JSON object with extracted features/hashes


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    threat_category = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), index=True, nullable=False)  # Low, Medium, High, Critical
    risk_score = Column(Integer, nullable=False)
    status = Column(String(32), default="New", index=True, nullable=False)  # New, Investigating, Contained, Resolved, False Positive
    assigned_analyst = Column(String(128), default="Unassigned", nullable=False)
    assigned_employee_id = Column(String(64), nullable=True, index=True)
    is_escalated = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime, default=utc_now, index=True, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    
    correlation_reason = Column(Text, nullable=True)
    correlation_confidence = Column(String(64), default="High (Deterministic Match)", nullable=True)
    forensic_summary = Column(Text, nullable=True)

    events = relationship("SecurityEvent", back_populates="incident")
    evidence_items = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("InvestigationNote", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), index=True, nullable=False)
    evidence_type = Column(String(64), nullable=False)  # IP, Domain, File Hash, Payload, Email Header, Secret Exposure
    evidence_value = Column(String(255), nullable=False)
    provenance = Column(String(255), nullable=False)  # Sensor/Log source
    confidence = Column(Float, default=1.0, nullable=False)
    captured_at = Column(DateTime, default=utc_now, nullable=False)

    incident = relationship("Incident", back_populates="evidence_items")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), index=True, nullable=False)
    analyst_name = Column(String(128), nullable=False)
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    incident = relationship("Incident", back_populates="notes")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), index=True, nullable=False)
    action_type = Column(String(64), nullable=False)  # IP_BLOCK, HOST_ISOLATION, SESSION_REVOKE, EMAIL_PURGE, SECRET_REVOKE, URL_BLOCK
    target = Column(String(255), nullable=False)
    status = Column(String(32), default="RECOMMENDED", nullable=False)  # RECOMMENDED, SIMULATED_EXECUTED, PENDING_APPROVAL, REVERTED
    details = Column(Text, nullable=False)
    is_simulated = Column(Boolean, default=True, nullable=False)
    executed_by = Column(String(128), nullable=True)
    executed_at = Column(DateTime, nullable=True)

    incident = relationship("Incident", back_populates="actions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)
    action = Column(String(64), index=True, nullable=False)
    actor = Column(String(128), nullable=False)
    resource_type = Column(String(64), index=True, nullable=False)
    resource_id = Column(String(64), index=True, nullable=False)
    details = Column(Text, nullable=True)
