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
  is_simulated?: boolean;
  is_acknowledged?: boolean;
  triage_status?: string | null;
  triage_reason?: string | null;
  triage_confidence?: number | null;
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
  l2_status?: string | null;
  l2_verdict?: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'NEEDS_HUMAN' | null;
  l2_confidence?: number | null;
  l2_summary?: string | null;
  l2_analysis?: string | null;
  needs_human?: boolean;
  l3_status?: string | null;
  disposition?: string | null;
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
  secret_leaks_total: number;
  active_employees_monitored: number;
  events_last_24h: number;
  events_prev_24h: number;
  critical_events_last_24h: number;
  suspicious_urls_total: number;
  zetaris_connected_sources: number;
  simulated_events_total?: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface ThreatSeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ActivityDataPoint {
  time_label: string;
  bucket_end?: string;
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
  employee_id?: string | null;
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

export interface ZetarisSourceState {
  source: string;
  table: string | null;
  watermark: string;
  last_run_at: string | null;
  last_status: 'OK' | 'ERROR' | null;
  last_error: string | null;
  rows_seen: number;
  events_created: number;
}

export interface ZetarisStatus {
  configured: boolean;
  connected: boolean;
  error: string | null;
  base_url: string;
  latency_ms?: number;
  databases?: string[];
  tables: Record<string, string | null>;
  sources: ZetarisSourceState[];
}

export interface ZetarisIngestReport {
  status: string;
  events_created: number;
  correlated_incidents: number;
  sources: Record<string, { status: string; rows?: number; events?: number; error?: string }>;
}

export interface Investigation {
  indicator: string;
  type: 'ip' | 'user';
  sources_queried: string[];
  stats: Record<string, number>;
  timeline: { time: string; source: string; ip: string | null; summary: string }[];
  suggested_blocks: { indicator: string; reason: string }[];
}

export interface SocOverview {
  l1: { events_total: number; triaged: number; waiting: number; auto_closed: number; duplicates: number; escalated: number };
  l2: { incidents_investigated: number; waiting: number; true_positive: number; needs_human: number; false_positive: number; auto_closed_incidents: number };
  l3: { pending: number; approved: number; rejected: number; pending_by_kind: Record<string, number>; active_rules: number };
  automation_rate: number | null;
}

export interface AgentRun {
  id: number;
  tier: 'L1' | 'L2';
  agent: string;
  subject_type: string;
  subject_id: string;
  decision: string;
  reason: string;
  confidence: number | null;
  duration_ms: number;
  created_at: string;
}

export interface DecisionRequest {
  id: number;
  kind: 'CONTAINMENT' | 'INCIDENT_DISPOSITION' | 'DETECTION_RULE' | 'DISABLE_ACCOUNT' | 'HOST_ISOLATION' | 'INCIDENT_CLOSURE';
  requires_admin?: boolean;
  incident_id: string | null;
  title: string;
  rationale: string;
  evidence: string[];
  proposal: Record<string, any>;
  priority: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  created_by: string;
  created_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  outcome: string | null;
}

export interface DetectionRule {
  id: number;
  name: string;
  description: string | null;
  kind: 'SUPPRESS' | 'ESCALATE';
  match: Record<string, string | number>;
  enabled: boolean;
  created_by: string;
  created_at: string;
  hit_count: number;
  last_hit_at: string | null;
}

export interface AdminOverview {
  alerts: { total: number; last_24h: number; critical_open: number; unacknowledged_high: number };
  incidents: { critical: number; unresolved: number; awaiting_approval: number; awaiting_admin: number };
  analysts: { total: number; active: number; online_now: number; never_signed_in: number; without_mfa: number };
  health: { name: string; status: 'ok' | 'warn' | 'down'; detail: string }[];
  data: { simulated_events: number; total_events: number; all_simulated: boolean; any_simulated: boolean };
  audit_entries: number;
}

export interface SettingDef {
  key: string;
  type: 'int' | 'choice';
  group: string;
  label: string;
  help: string;
  value: number | string;
  default: number | string;
  min?: number;
  max?: number;
  choices?: string[];
  updated_by: string | null;
  updated_at: string | null;
}

export interface PermissionRow {
  capability: string;
  [role: string]: boolean | string;
}

export interface IntegrationRow {
  name: string;
  configured: boolean;
  detail: string;
  recipients?: string[];
  synthetic?: boolean;
}

export interface Assignable {
  id: number;
  full_name: string;
  email: string;
  role: UserRole;
}

export interface EventDetail {
  event: SecurityEvent;
  related_events: SecurityEvent[];
  timeline: { time: string; event_id: string; category: string; severity: Severity; source: string; this: boolean }[];
  automation: { tier: string; decision: string; reason: string; confidence: number | null; at: string }[];
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
  monitoring_policy: string;
  is_active: boolean;
  risk_score?: number;
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
  delivery_status: 'QUEUED' | 'SENDING' | 'SENT' | 'FAILED' | 'NOT_CONFIGURED' | 'SUPPRESSED_DUPLICATE';
  retry_count: number;
  incident_id?: string | null;
  event_id?: string | null;
  sent_at: string;
  dispatched_at?: string | null;
  last_error?: string | null;
}

export interface AdminUser {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  employee_id: string | null;
  department: string | null;
  created_at: string;
  last_login: string | null;
  mfa_enabled: boolean;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  details: string | null;
  request_id: string | null;
  ip_address: string | null;
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

