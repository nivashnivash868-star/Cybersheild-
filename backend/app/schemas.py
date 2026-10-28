from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, ConfigDict, EmailStr

# --- Authentication & Users ---
class UserLoginRequest(BaseModel):
    email: str = Field(..., max_length=255, description="Company user email")
    password: str = Field(..., min_length=1, max_length=256)

class UserProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    employee_id: Optional[str] = None
    department: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False

class SessionStateResponse(BaseModel):
    """What the SPA needs after login / on reload. No credential is returned: the session is an HttpOnly cookie."""
    user: UserProfileResponse
    mfa_state: str = Field(..., description="ok | verify | enroll")
    must_change_password: bool = False

class MfaCodeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str

class MfaDisableRequest(BaseModel):
    password: str = Field(..., max_length=256)
    code: str = Field(..., min_length=6, max_length=8)

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., max_length=255)

class PasswordResetRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=200)
    new_password: str = Field(..., min_length=1, max_length=256)

class UserProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, max_length=128)
    department: Optional[str] = Field(None, max_length=128)
    phone_number: Optional[str] = Field(None, max_length=64)

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=256)
    new_password: str = Field(..., max_length=256)

class UserCreateRequest(BaseModel):
    email: str = Field(..., max_length=255)
    full_name: str = Field(..., max_length=128)
    role: str
    department: Optional[str] = Field(None, max_length=128)
    employee_id: Optional[str] = Field(None, max_length=64)
    temporary_password: str = Field(..., max_length=256)

class UserAdminUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

class EmployeeCreateRequest(BaseModel):
    employee_id: str = Field(..., min_length=3, max_length=64, description="Unique employee identifier e.g. EMP-1042")
    full_name: str = Field(..., min_length=2, max_length=128)
    company_email: str = Field(..., max_length=255)
    phone_number: Optional[str] = None
    department: str = Field(..., min_length=2, max_length=128)
    role_title: str = Field(..., min_length=2, max_length=128)
    monitoring_policy: str = Field(default="Standard Workstation", description="Standard Workstation, Executive High-Risk, DevOps & Cloud Admin, Contractor Strict")

class EmployeeUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    department: Optional[str] = None
    role_title: Optional[str] = None
    monitoring_policy: Optional[str] = None
    is_active: Optional[bool] = None

class EmployeeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    employee_id: str
    full_name: str
    company_email: str
    phone_number: Optional[str] = None
    department: str
    role_title: str
    monitoring_policy: str
    is_active: bool
    risk_score: int
    created_at: datetime
    updated_at: datetime

# --- Monitoring Sources ---
class MonitoringSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_id: str
    name: str
    source_type: str
    status: str
    events_ingested_count: int
    last_heartbeat: datetime
    is_simulated: bool
    configuration_json: Optional[str] = None

# --- DLP & Company Secret Detection ---
class DLPScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=500000)
    source_location: str = Field(default="Analyst Ad-Hoc Scanner")
    employee_id: Optional[str] = None
    employee_email: Optional[str] = None

class SecretFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: str
    secret_type: str
    masked_value: str
    source_location: str
    employee_id: Optional[str] = None
    employee_email: Optional[str] = None
    severity: str
    risk_score: int
    status: str
    recommendations: str
    detected_at: datetime

# --- URL Warning & Safe Interstitial ---
class URLWarningInspectRequest(BaseModel):
    url: str = Field(..., min_length=3)
    employee_email: Optional[str] = None
    referrer: Optional[str] = None

class URLWarningInspectResponse(BaseModel):
    target_url: str
    domain: str
    threat_category: str
    risk_score: int
    severity: str
    is_blocked: bool
    is_simulated_block: bool
    blocking_reason: str
    advisory_message: str
    safe_return_url: str = "about:blank"
    can_proceed_override: bool = True
    soc_alert_generated: bool = True

class URLOverrideLogRequest(BaseModel):
    url: str
    employee_email: str
    override_reason: str = Field(..., min_length=5)

# --- Automated Alerts & Notifications ---
class NotificationDeliveryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    delivery_id: str
    recipient_type: str
    recipient_address: str
    channel: str
    severity: str
    title: str
    body_preview: str
    delivery_status: str
    retry_count: int
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    sent_at: datetime
    dispatched_at: Optional[datetime] = None
    last_error: Optional[str] = None

# --- Phishing & Scam Detection ---
class PhishingAnalysisRequest(BaseModel):
    submission_type: str = Field(..., description="url, email, or sms")
    content: str = Field(..., min_length=1, max_length=50000, description="URL or message text")
    email_subject: Optional[str] = Field(None, description="Optional email subject line")
    sender_info: Optional[str] = Field(None, description="Sender email address or phone number")
    reporting_employee_email: Optional[str] = None

class IndicatorDetail(BaseModel):
    category: str
    signal: str
    weight: int
    severity: str
    description: str

class PhishingAnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: datetime
    submission_type: str
    target: str
    risk_score: int
    risk_category: str
    detection_engine: str
    indicators: List[IndicatorDetail]
    explanation: str
    recommended_precautions: List[str]
    features_extracted: Dict[str, Any]
    reputation_status: str

# --- File Analysis ---
class FileAnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    filesize_bytes: int
    mime_type: str
    sha256: str
    sha1: str
    md5: str
    entropy: float
    risk_score: int
    risk_category: str
    detection_engine: str
    is_pe_executable: bool
    suspicious_patterns: List[str]
    metadata: Dict[str, Any]
    reputation_lookup: Dict[str, Any]
    explanation: str
    recommended_precautions: List[str]
    disclaimer: str

# --- Network Anomaly Detection ---
class NetworkRecordInput(BaseModel):
    timestamp: Optional[str] = None
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str = "TCP"
    bytes_transferred: int = 0
    packet_count: int = 1
    connection_state: Optional[str] = "ESTABLISHED"
    auth_status: Optional[str] = "SUCCESS"  # SUCCESS, FAILED
    user_account: Optional[str] = None

class NetworkAnomalyAlert(BaseModel):
    event_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    event_type: str
    severity: str
    risk_score: int
    detection_reason: str
    recommended_response: str
    evidence_tokens: List[str]
    engine: str

class NetworkAnalysisBatchResponse(BaseModel):
    total_records_analyzed: int
    anomalies_detected: int
    benign_count: int
    engine_used: str
    alerts: List[NetworkAnomalyAlert]

# --- Security Events ---
class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    event_id: str
    timestamp: datetime
    event_source: str
    threat_category: str
    risk_score: int
    severity: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    user_account: Optional[str] = None
    employee_id: Optional[str] = None
    evidence: str
    analysis_status: str
    recommended_action: str
    is_acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    incident_id: Optional[str] = None

class AcknowledgeEventRequest(BaseModel):
    analyst_name: Optional[str] = None  # ignored: the actor is always the signed-in user

# --- Incidents & Response ---
class IncidentEvidenceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_type: str
    evidence_value: str
    provenance: str
    confidence: float
    captured_at: datetime

class InvestigationNoteItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analyst_name: str
    note_text: str
    created_at: datetime

class ResponseActionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_type: str
    target: str
    status: str
    details: str
    is_simulated: bool
    executed_by: Optional[str]
    executed_at: Optional[datetime]

class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    description: str
    threat_category: str
    severity: str
    risk_score: int
    status: str
    assigned_analyst: str
    assigned_employee_id: Optional[str] = None
    is_escalated: bool = False
    created_at: datetime
    updated_at: datetime
    correlation_reason: Optional[str] = None
    correlation_confidence: Optional[str] = None
    forensic_summary: Optional[str] = None
    evidence_items: List[IncidentEvidenceItem] = []
    notes: List[InvestigationNoteItem] = []
    actions: List[ResponseActionItem] = []
    events: List[SecurityEventResponse] = []

class IncidentStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="New, Investigating, Contained, Resolved, False Positive")
    analyst_name: Optional[str] = Field(None, description="Ignored: the actor is always the signed-in user.")
    comment: Optional[str] = Field(None, max_length=2000)

class IncidentAssignRequest(BaseModel):
    assigned_analyst: str = Field(..., max_length=128)

class AddNoteRequest(BaseModel):
    analyst_name: Optional[str] = Field(None, description="Ignored: the actor is always the signed-in user.")
    note_text: str = Field(..., min_length=1, max_length=5000)

class ExecuteResponseActionRequest(BaseModel):
    action_type: str = Field(..., description="FIREWALL_BLOCK, IP_BLOCK, URL_BLOCK, DOMAIN_BLOCK publish to the blocklist; the rest are recorded as manual.")
    target: str = Field(..., max_length=512)
    details: Optional[str] = Field("", max_length=2000)
    ttl_hours: Optional[int] = Field(None, ge=1, le=24 * 30)

# --- Forensics ---
class ForensicArtifact(BaseModel):
    type: str
    value: str
    relation: str
    first_seen: str
    last_seen: str
    risk_score: int

class ForensicInvestigationResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    investigator: str
    created_at: str
    timeline: List[Dict[str, Any]]
    artifacts: List[ForensicArtifact]
    provenance_chain: List[str]
    analyst_findings: str
    mitre_attack_tactics: List[str]
    is_simulated_notice: str

# --- Dashboard & System ---
class DashboardMetrics(BaseModel):
    total_events_analyzed: int
    threats_detected: int
    critical_incidents: int
    high_incidents: int
    phishing_scans_total: int
    network_anomalies_total: int
    secret_leaks_total: int = 0
    active_employees_monitored: int = 0
    open_investigations: int
    system_status: str
    db_mode: str
    reputation_service_status: str
    ml_models_active: bool

class ThreatSeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class ActivityDataPoint(BaseModel):
    time_label: str
    total_events: int
    threats: int
    phishing: int
    network: int

class SystemStatusResponse(BaseModel):
    name: str
    version: str
    environment: str
    status: str
    database: Dict[str, Any]
    integrations: Dict[str, Any]
    ml_engine: Dict[str, Any]
    security_guards: Dict[str, Any]
