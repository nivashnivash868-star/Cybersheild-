from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)


def naive_utc_now():
    """UTC without tzinfo; matches how DateTime columns come back from SQLite and Postgres."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

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

    # Credential hygiene and brute-force protection
    password_changed_at = Column(DateTime, nullable=True)
    must_change_password = Column(Boolean, default=False, nullable=False)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # TOTP multi-factor authentication. Secrets are stored encrypted (see utils/crypto.py).
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    totp_secret_enc = Column(Text, nullable=True)
    totp_pending_enc = Column(Text, nullable=True)
    totp_last_counter = Column(Integer, nullable=True)  # blocks replay of the last accepted code


class UserSession(Base):
    """Server-side session. Only the SHA-256 of the cookie token is stored."""
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=naive_utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    mfa_verified = Column(Boolean, default=False, nullable=False)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("User")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


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
    delivery_status = Column(String(32), default="QUEUED", index=True, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    incident_id = Column(String(64), nullable=True, index=True)
    event_id = Column(String(64), nullable=True, index=True)
    dedup_key = Column(String(128), nullable=True, index=True)
    sent_at = Column(DateTime, default=utc_now, index=True, nullable=False)  # when the alert was queued

    # Outbox state. delivery_status: QUEUED -> SENT | FAILED (retries first) | NOT_CONFIGURED | SUPPRESSED_DUPLICATE.
    # SENT means the SMTP server / SMS provider accepted the message, not that the recipient read it.
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    dispatched_at = Column(DateTime, nullable=True)
    last_error = Column(String(500), nullable=True)
    provider_message_id = Column(String(128), nullable=True)
    message_body = Column(Text, nullable=True)  # full text to send; wiped after sending when redact_after_send
    redact_after_send = Column(Boolean, default=False, nullable=False)


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

    # True for fabricated telemetry (demo seed, simulate-pulse, synthetic test data). Surfaced in the UI as "SIMULATED".
    is_simulated = Column(Boolean, default=False, index=True, nullable=False)

    # SOC Level 1 (automated triage). NEW -> DUPLICATE | AUTO_CLOSED | ESCALATED
    triage_status = Column(String(16), default="NEW", index=True, nullable=False)
    triage_rule = Column(String(48), nullable=True)
    triage_reason = Column(String(500), nullable=True)
    triage_confidence = Column(Float, nullable=True)
    triaged_at = Column(DateTime, nullable=True)
    duplicate_of = Column(String(64), nullable=True)

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

    # SOC Level 2 (automated investigation). l2_status: PENDING -> DONE
    l2_status = Column(String(16), default="PENDING", index=True, nullable=False)
    l2_verdict = Column(String(24), nullable=True)  # TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_HUMAN
    l2_confidence = Column(Float, nullable=True)
    l2_summary = Column(Text, nullable=True)
    l2_analysis = Column(Text, nullable=True)  # JSON: steps, kill chain, entities, recommendations
    l2_completed_at = Column(DateTime, nullable=True)
    # SOC Level 3 (human decision). l3_status: NONE | AWAITING_DECISION | DECIDED
    needs_human = Column(Boolean, default=False, index=True, nullable=False)
    l3_status = Column(String(24), default="NONE", index=True, nullable=False)
    disposition = Column(String(32), nullable=True)  # CONFIRMED_TRUE_POSITIVE | FALSE_POSITIVE

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

    # Filled automatically on flush (see utils/audit.py). entry_hash = HMAC(prev_hash + record).
    request_id = Column(String(64), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=True, index=True)


class BlocklistEntry(Base):
    """An indicator proposed for blocking. Only ACTIVE entries are published in the feeds."""
    __tablename__ = "blocklist_entries"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(16), index=True, nullable=False)  # ip, cidr, domain, url
    value = Column(String(512), index=True, nullable=False)
    reason = Column(Text, nullable=False)
    incident_id = Column(String(64), nullable=True, index=True)
    # PENDING_APPROVAL -> ACTIVE -> EXPIRED | REVOKED ; PENDING_APPROVAL -> REJECTED
    status = Column(String(24), default="PENDING_APPROVAL", index=True, nullable=False)
    ttl_hours = Column(Integer, nullable=False)
    proposed_by = Column(String(128), nullable=False)
    proposed_at = Column(DateTime, default=naive_utc_now, nullable=False)
    decided_by = Column(String(128), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_note = Column(String(500), nullable=True)
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)


class AgentRun(Base):
    """Every decision the automated SOC tiers make, so humans can audit, trust and reverse them."""
    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    tier = Column(String(4), index=True, nullable=False)  # L1 | L2
    agent = Column(String(32), nullable=False)
    subject_type = Column(String(16), nullable=False)  # event | incident
    subject_id = Column(String(64), index=True, nullable=False)
    decision = Column(String(32), index=True, nullable=False)
    reason = Column(Text, nullable=False)
    confidence = Column(Float, nullable=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, index=True, nullable=False)


class DecisionRequest(Base):
    """Something the automated tiers will not do on their own: a human (SOC Level 3) must decide."""
    __tablename__ = "decision_requests"

    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String(24), index=True, nullable=False)  # CONTAINMENT | INCIDENT_DISPOSITION | DETECTION_RULE
    incident_id = Column(String(64), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    rationale = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON list of supporting facts
    proposal = Column(Text, nullable=False)  # JSON: what will happen on approval
    priority = Column(String(16), default="Medium", index=True, nullable=False)
    status = Column(String(12), default="PENDING", index=True, nullable=False)  # PENDING | APPROVED | REJECTED
    created_by = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, index=True, nullable=False)
    decided_by = Column(String(128), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_note = Column(String(500), nullable=True)
    outcome = Column(String(255), nullable=True)


class DetectionRule(Base):
    """Detection engineering: rules L1 applies. Created by humans, or proposed by L2 and approved by a human."""
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(500), nullable=True)
    kind = Column(String(12), index=True, nullable=False)  # SUPPRESS | ESCALATE
    match_json = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, index=True, nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, nullable=False)
    source_decision_id = Column(Integer, nullable=True)
    hit_count = Column(Integer, default=0, nullable=False)
    last_hit_at = Column(DateTime, nullable=True)


class SecuritySetting(Base):
    """Administrator-tunable security configuration and small operational facts (e.g. the worker heartbeat)."""
    __tablename__ = "security_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
    updated_by = Column(String(128), nullable=True)
    updated_at = Column(DateTime, default=naive_utc_now, nullable=False)


class IngestState(Base):
    """Progress of one Zetaris ingestion source (auth / network / email)."""
    __tablename__ = "ingest_state"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(32), unique=True, index=True, nullable=False)
    watermark = Column(DateTime, nullable=False)  # only rows newer than this are read next time
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(16), nullable=True)  # OK | ERROR
    last_error = Column(String(500), nullable=True)
    rows_seen = Column(Integer, default=0, nullable=False)
    events_created = Column(Integer, default=0, nullable=False)


class FeedToken(Base):
    """Credential a firewall / DNS sinkhole uses to pull the blocklist. Only the hash is stored."""
    __tablename__ = "feed_tokens"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=naive_utc_now, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    last_fetched_at = Column(DateTime, nullable=True)
    last_fetched_version = Column(String(64), nullable=True)
    last_fetched_ip = Column(String(64), nullable=True)


class ResponseJob(Base):
    """One approved action handed to the organisation's own automation (identity provider, EDR, SOAR) through a signed webhook.

    QUEUED -> SENDING -> SENT                (the receiver accepted the request; the work is not yet confirmed)
                      -> COMPLETED           (the receiver reported success, in its reply or a signed callback)
                      -> FAILED              (the receiver refused, reported failure, or retries ran out)
    SENT -> UNCONFIRMED                      (no report back within RESPONSE_WEBHOOK_ACK_MINUTES)
    """
    __tablename__ = "response_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(40), unique=True, index=True, nullable=False)
    action = Column(String(32), index=True, nullable=False)          # DISABLE_ACCOUNT | HOST_ISOLATION | PING
    target = Column(String(255), nullable=False)
    decision_id = Column(Integer, nullable=True, index=True)
    incident_id = Column(String(64), nullable=True, index=True)
    approved_by = Column(String(128), nullable=False)
    status = Column(String(16), default="QUEUED", index=True, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    http_status = Column(Integer, nullable=True)
    last_error = Column(String(500), nullable=True)
    result_detail = Column(String(500), nullable=True)
    response_action_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=naive_utc_now, nullable=False)
    sent_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class ThreatIntelRecord(Base):
    """Cached answer from a reputation provider for one indicator. Lookups are rate-limited and paid for, so they are kept."""
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), index=True, nullable=False)
    provider = Column(String(24), index=True, nullable=False)
    status = Column(String(16), nullable=False)            # ok | not_found | error
    result_json = Column(Text, nullable=False)
    fetched_at = Column(DateTime, default=naive_utc_now, index=True, nullable=False)
