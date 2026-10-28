export type Severity = 'Low' | 'Medium' | 'High' | 'Critical';
export type IncidentStatus = 'New' | 'Investigating' | 'Contained' | 'Resolved' | 'False Positive';

export interface IndicatorDetail {
  category: string;
  signal: string;
  weight: number;
  severity: Severity;
  description: string;
}

export interface PhishingAnalysisResult {
  analysis_id: string;
  timestamp: string;
  submission_type: 'url' | 'email' | 'sms';
  target: string;
  risk_score: number;
  risk_category: Severity;
  detection_engine: string;
  indicators: IndicatorDetail[];
  explanation: string;
  recommended_precautions: string[];
  features_extracted: Record<string, any>;
  reputation_status: string;
}

export interface FileAnalysisResult {
  analysis_id: string;
  filename: string;
  filesize_bytes: number;
  mime_type: string;
  sha256: string;
  sha1: string;
  md5: string;
  entropy: number;
  risk_score: number;
  risk_category: Severity;
  detection_engine: string;
  is_pe_executable: boolean;
  suspicious_patterns: string[];
  metadata: Record<string, any>;
  reputation_lookup: Record<string, any>;
  explanation: string;
  recommended_precautions: string[];
  disclaimer: string;
}

export interface NetworkAnomalyAlert {
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  event_type: string;
  severity: Severity;
  risk_score: number;
  detection_reason: string;
  recommended_response: string;
  evidence_tokens: string[];
  engine: string;
}

export interface NetworkAnalysisBatchResult {
  total_records_analyzed: number;
  anomalies_detected: number;
  benign_count: number;
  engine_used: string;
  alerts: NetworkAnomalyAlert[];
}

export interface SecurityEvent {
  id?: number;
  event_id: string;
  timestamp: string;
  event_source: string;
  threat_category: string;
  risk_score: number;
  severity: Severity;
  source_ip?: string | null;
  dest_ip?: string | null;
  domain?: string | null;
  file_hash?: string | null;
  user_account?: string | null;
  evidence: string;
  analysis_status: string;
  recommended_action: string;
  incident_id?: string | null;
}

export interface IncidentEvidenceItem {
  evidence_type: string;
  evidence_value: string;
  provenance: string;
  confidence: number;
  captured_at: string;
}

export interface InvestigationNoteItem {
  id: number;
  analyst_name: string;
  note_text: string;
  created_at: string;
}

export interface ResponseActionItem {
  id: number;
  action_type: string;
  target: string;
  status: string;
  details: string;
  is_simulated: boolean;
  executed_by?: string | null;
  executed_at?: string | null;
}

export interface IncidentDetail {
  incident_id: string;
  title: string;
  description: string;
  threat_category: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  assigned_analyst: string;
  created_at: string;
  updated_at: string;
  correlation_reason?: string | null;
  correlation_confidence?: string | null;
  forensic_summary?: string | null;
  evidence_items: IncidentEvidenceItem[];
  notes: InvestigationNoteItem[];
  actions: ResponseActionItem[];
  events: SecurityEvent[];
}

export interface DashboardMetrics {
  total_events_analyzed: number;
  threats_detected: number;
  critical_incidents: number;
  high_incidents: number;
  phishing_scans_total: number;
  network_anomalies_total: number;
  open_investigations: number;
  system_status: string;
  db_mode: string;
  reputation_service_status: string;
  ml_models_active: boolean;
}

export interface ThreatSeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ActivityDataPoint {
  time_label: string;
  total_events: number;
  threats: number;
  phishing: number;
  network: number;
}

export interface ForensicArtifact {
  type: string;
  value: string;
  relation: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
}

export interface ForensicInvestigation {
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  investigator: string;
  created_at: string;
  timeline: Array<{
    timestamp: string;
    event_type: string;
    source: string;
    category: string;
    severity: string;
    description: string;
    pivot_data: Record<string, any>;
  }>;
  artifacts: ForensicArtifact[];
  provenance_chain: string[];
  analyst_findings: string;
  mitre_attack_tactics: string[];
  is_simulated_notice: string;
}

export interface SystemStatusData {
  name: string;
  version: string;
  environment: string;
  status: string;
  database: {
    provider: string;
    is_demo_mode: boolean;
    status: string;
    notice: string;
    target: string;
  };
  integrations: Record<string, {
    configured: boolean;
    status: string;
    details: string;
  }>;
  ml_engine: Record<string, string>;
  security_guards: Record<string, string>;
}

// Enterprise RBAC & Auth Types
export type UserRole = 'Super Admin' | 'Security Administrator' | 'SOC Analyst' | 'Employee';

export interface UserSession {
  id: number;
  email: string;
  name: string;
  role: UserRole;
  department: string;
  is_active: boolean;
  mfa_enabled: boolean;
}

/** `ok` = fully signed in; `verify` = enter a TOTP code; `enroll` = this role must set up MFA first. */
export interface SessionState {
  user: UserSession;
  mfa_state: 'ok' | 'verify' | 'enroll';
  must_change_password: boolean;
}

export interface BlocklistEntry {
  id: number;
  indicator_type: 'ip' | 'cidr' | 'domain' | 'url';
  value: string;
  reason: string;
  incident_id: string | null;
  status: 'PENDING_APPROVAL' | 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'REJECTED';
  ttl_hours: number;
  proposed_by: string;
  proposed_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  activated_at: string | null;
  expires_at: string | null;
}

export interface FeedTokenInfo {
  id: number;
  name: string;
  created_by: string;
  created_at: string;
  revoked_at: string | null;
  last_fetched_at: string | null;
  last_fetched_version: string | null;
  last_fetched_ip: string | null;
}

// Employee Management Types
export interface Employee {
  id: number;
  employee_id: string;
  full_name: string;
  company_email: string;
  phone_number?: string | null;
  department: string;
  role_title: string;
  monitoring_policy: 'Strict' | 'High' | 'Standard' | 'Low';
  is_active: boolean;
  risk_level: Severity;
  recent_events_count?: number;
  created_at: string;
  updated_at: string;
}

// 24/7 Security Monitoring Engine Types
export interface MonitoringSource {
  id: number;
  source_id: string;
  name: string;
  source_type: string;
  description: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  event_count: number;
  last_heartbeat: string;
  is_simulated: boolean;
  config_meta?: Record<string, any>;
}

// Company Secret Detection (DLP) Types
export interface SecretFinding {
  id: number;
  finding_id: string;
  secret_type: string;
  masked_value: string;
  secret_hash: string;
  source_type: string;
  location_reference: string;
  exposure_scope: string;
  risk_score: number;
  severity: Severity;
  status: 'Active' | 'Remediated' | 'Revoked' | 'False Positive';
  employee_email?: string | null;
  detected_at: string;
  remediation_notes?: string | null;
}

// Notification Deliveries Types
export interface NotificationDelivery {
  id: number;
  delivery_id: string;
  recipient_type: 'SOC_ANALYST' | 'EMPLOYEE';
  recipient_address: string;
  channel: 'EMAIL' | 'SMS' | 'IN_APP';
  severity: Severity;
  title: string;
  body_preview: string;
  delivery_status: 'DELIVERED' | 'SUPPRESSED_DUPLICATE' | 'FAILED' | 'PENDING';
  retry_count: number;
  incident_id?: string | null;
  event_id?: string | null;
  sent_at: string;
}

// URL Interstitial Inspection Types
export interface URLInspectionResult {
  target_url: string;
  domain: string;
  threat_category: string;
  risk_score: number;
  severity: Severity;
  is_blocked: boolean;
  is_simulated_block: boolean;
  blocking_reason: string;
  advisory_message: string;
  safe_return_url: string;
  can_proceed_override: boolean;
  soc_alert_generated: boolean;
}

