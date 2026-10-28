import {
  DashboardMetrics, ThreatSeverityDistribution, ActivityDataPoint,
  SecurityEvent, PhishingAnalysisResult, FileAnalysisResult,
  NetworkAnalysisBatchResult, IncidentDetail, ForensicInvestigation,
  SystemStatusData, UserSession, SessionState, BlocklistEntry, FeedTokenInfo, Employee, MonitoringSource,
  SecretFinding, NotificationDelivery, URLInspectionResult
} from '../types';

const BASE_URL = (import.meta.env.VITE_API_URL as string) || '/api/v1';

/** Fired when a request that needed a session gets 401, so the app can return to the sign-in screen. */
export const UNAUTHORIZED_EVENT = 'cybershield:unauthorized';

const CSRF_COOKIE = 'cs_csrf';

function readCookie(name: string): string {
  const match = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

/** The session itself is an HttpOnly cookie the page can't read; only this CSRF token is exposed to scripts. */
function csrfHeaders(method: string): Record<string, string> {
  if (['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) return {};
  const token = readCookie(CSRF_COOKIE);
  return token ? { 'X-CSRF-Token': token } : {};
}

async function throwForResponse(res: Response, endpoint: string): Promise<never> {
  const errorText = await res.text();
  let errorMsg = `API Error ${res.status}: ${res.statusText}`;
  try {
    const parsed = JSON.parse(errorText);
    if (typeof parsed.detail === 'string') errorMsg = parsed.detail;
    else if (Array.isArray(parsed.detail)) errorMsg = parsed.detail.map((d: any) => d.msg).join('; ');
  } catch {
    if (errorText) errorMsg = errorText;
  }
  const isAuthProbe = endpoint === '/auth/me' || endpoint === '/auth/login';
  if (res.status === 401 && !isAuthProbe) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  throw new Error(errorMsg);
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const method = options?.method ?? 'GET';
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...csrfHeaders(method),
    ...(options?.headers as Record<string, string>),
  };

  const res = await fetch(`${BASE_URL}${endpoint}`, { ...options, headers, credentials: 'include' });
  if (!res.ok) await throwForResponse(res, endpoint);
  return res.json() as Promise<T>;
}

async function requestText(endpoint: string): Promise<string> {
  const res = await fetch(`${BASE_URL}${endpoint}`, { credentials: 'include' });
  if (!res.ok) await throwForResponse(res, endpoint);
  return res.text();
}

const toSession = (u: any): UserSession => ({
  id: u.id,
  email: u.email,
  name: u.full_name || u.name,
  role: u.role,
  department: u.department || 'Security Operations',
  is_active: u.is_active,
  mfa_enabled: !!u.mfa_enabled,
});

const toState = (res: any): SessionState => ({
  user: toSession(res.user),
  mfa_state: res.mfa_state,
  must_change_password: !!res.must_change_password,
});

export const api = {
  // Authentication & RBAC
  login: async (credentials: { email: string; password: string }): Promise<SessionState> =>
    toState(await request<any>('/auth/login', { method: 'POST', body: JSON.stringify(credentials) })),
  getMe: async (): Promise<SessionState> => toState(await request<any>('/auth/me')),
  mfaSetup: () => request<{ secret: string; otpauth_uri: string }>('/auth/mfa/setup', { method: 'POST' }),
  mfaEnable: async (code: string): Promise<SessionState> =>
    toState(await request<any>('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) })),
  mfaVerify: async (code: string): Promise<SessionState> =>
    toState(await request<any>('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) })),
  updateProfile: async (payload: { full_name?: string; department?: string; phone_number?: string }): Promise<UserSession> =>
    toSession(await request<any>('/auth/profile', { method: 'PUT', body: JSON.stringify(payload) })),
  changePassword: (payload: { current_password: string; new_password: string }) =>
    request<{ status: string; message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  logout: () => request<{ status: string }>('/auth/logout', { method: 'POST' }),
  forgotPassword: (email: string) =>
    request<{ status: string; message: string }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
  resetPassword: (payload: { token: string; new_password: string }) =>
    request<{ status: string; message: string }>('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Blocklist (prevention)
  getBlocklist: (status?: string) =>
    request<BlocklistEntry[]>(`/blocklist${status && status !== 'All' ? `?status=${status}` : ''}`),
  proposeBlock: (payload: { indicator: string; reason: string; ttl_hours?: number; incident_id?: string }) =>
    request<BlocklistEntry>('/blocklist', { method: 'POST', body: JSON.stringify(payload) }),
  decideBlock: (id: number, decision: 'approve' | 'reject' | 'revoke', note?: string) =>
    request<BlocklistEntry>(`/blocklist/${id}/${decision}`, { method: 'POST', body: JSON.stringify({ note }) }),
  getFeedTokens: () => request<FeedTokenInfo[]>('/blocklist/feeds'),
  createFeedToken: (name: string) =>
    request<{ id: number; name: string; token: string; urls: Record<string, string>; note: string }>(
      '/blocklist/feeds',
      { method: 'POST', body: JSON.stringify({ name }) }
    ),
  revokeFeedToken: (id: number) => request<{ status: string }>(`/blocklist/feeds/${id}`, { method: 'DELETE' }),

  // Employee Management
  getEmployees: (params?: { department?: string; policy?: string; search?: string }) => {
    const query = new URLSearchParams();
    if (params?.department && params.department !== 'All') query.set('department', params.department);
    if (params?.policy && params.policy !== 'All') query.set('policy', params.policy);
    if (params?.search) query.set('search', params.search);
    return request<Employee[]>(`/employees?${query.toString()}`);
  },
  createEmployee: (employee: Partial<Employee>) =>
    request<Employee>('/employees', {
      method: 'POST',
      body: JSON.stringify(employee),
    }),
  updateEmployee: (id: number, updates: Partial<Employee>) =>
    request<Employee>(`/employees/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),
  bulkImportEmployees: (records: any[]) =>
    request<{ status: string; imported_count: number; duplicates_skipped: number; errors: string[] }>(
      '/employees/import',
      {
        method: 'POST',
        body: JSON.stringify(records),
      }
    ),
  getEmployeeEvents: (employeeId: string) =>
    request<SecurityEvent[]>(`/employees/${employeeId}/events`),

  // 24/7 Monitoring Sources
  getMonitoringSources: () => request<MonitoringSource[]>('/monitoring/sources'),
  getMonitoringHeartbeat: () =>
    request<{ status: string; active_sources_count: number; sources: MonitoringSource[]; timestamp: string }>(
      '/monitoring/heartbeat'
    ),
  simulateMonitoringPulse: () =>
    request<{ status: string; pulse_events_generated: number; new_events: SecurityEvent[] }>(
      '/monitoring/simulate-pulse',
      { method: 'POST' }
    ),

  // Company Secret Detection (DLP)
  scanDLP: (payload: { content: string; source_location?: string; employee_id?: string; employee_email?: string }) =>
    request<SecretFinding[]>('/dlp/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getDLPFindings: (params?: { status?: string; secret_type?: string }) => {
    const query = new URLSearchParams();
    if (params?.status && params.status !== 'All') query.set('status', params.status);
    if (params?.secret_type && params.secret_type !== 'All') query.set('secret_type', params.secret_type);
    return request<SecretFinding[]>(`/dlp/findings?${query.toString()}`);
  },
  updateDLPFindingStatus: (id: number, payload: { status: string; remediation_notes?: string }) =>
    request<{ status: string; updated_status: string }>(`/dlp/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  // URL Interstitial Warning & Override
  inspectUrl: (url: string, employee_email?: string) =>
    request<URLInspectionResult>('/url/inspect', {
      method: 'POST',
      body: JSON.stringify({ url, employee_email }),
    }),
  overrideUrlWarning: (payload: { url: string; employee_email: string; override_reason: string }) =>
    request<{ status: string; message: string; audit_id: number }>('/url/override', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Automated Alerts & Notification Deliveries
  getNotificationDeliveries: (params?: { recipient_type?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.recipient_type && params.recipient_type !== 'All') query.set('recipient_type', params.recipient_type);
    if (params?.limit) query.set('limit', String(params.limit));
    return request<NotificationDelivery[]>(`/alerts/deliveries?${query.toString()}`);
  },
  testDispatchAlert: (payload: { title: string; summary: string; severity: string; target_employee_email?: string }) =>
    request<{ status: string; deliveries_count: number; deliveries: NotificationDelivery[] }>('/alerts/test-dispatch', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Dashboard
  getDashboardMetrics: () => request<DashboardMetrics>('/dashboard/metrics'),
  getSeverityDistribution: () => request<ThreatSeverityDistribution>('/dashboard/severity-distribution'),
  getActivityTimeline: () => request<ActivityDataPoint[]>('/dashboard/activity-timeline'),
  getRecentEvents: (params?: { severity?: string; search?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.severity && params.severity !== 'All') query.set('severity', params.severity);
    if (params?.search) query.set('search', params.search);
    if (params?.limit) query.set('limit', String(params.limit));
    return request<SecurityEvent[]>(`/dashboard/recent-events?${query.toString()}`);
  },

  // Phishing & Scam
  analyzePhishing: (payload: { submission_type: string; content: string; email_subject?: string; sender_info?: string }) =>
    request<PhishingAnalysisResult>('/phishing/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getPhishingSamples: () => request<any[]>('/phishing/samples'),

  // File Analysis
  analyzeFile: async (file: File): Promise<FileAnalysisResult> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${BASE_URL}/files/analyze`, {
      method: 'POST',
      headers: csrfHeaders('POST'),
      credentials: 'include',
      body: formData,
    });
    if (!res.ok) await throwForResponse(res, '/files/analyze');
    return res.json();
  },
  analyzeSampleFile: (sampleType: string) =>
    request<FileAnalysisResult>('/files/sample-test', {
      method: 'POST',
      body: JSON.stringify({ sample_type: sampleType }),
    }),
  getFileSamples: () => request<any[]>('/files/samples'),

  // Network Anomaly
  analyzeNetworkBatch: (records: any[]) =>
    request<NetworkAnalysisBatchResult>('/network/analyze-batch', {
      method: 'POST',
      body: JSON.stringify(records),
    }),
  getNetworkSamples: () => request<any[]>('/network/sample-scenarios'),

  // Incidents
  getIncidents: (params?: { status?: string; severity?: string; search?: string }) => {
    const query = new URLSearchParams();
    if (params?.status && params.status !== 'All') query.set('status', params.status);
    if (params?.severity && params.severity !== 'All') query.set('severity', params.severity);
    if (params?.search) query.set('search', params.search);
    return request<IncidentDetail[]>(`/incidents?${query.toString()}`);
  },
  getIncidentDetail: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  updateIncidentStatus: (id: string, payload: { status: string; analyst_name?: string; comment?: string }) =>
    request<{ status: string; new_status: string }>(`/incidents/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  assignIncidentAnalyst: (id: string, assigned_analyst: string) =>
    request<{ status: string; assigned_analyst: string }>(`/incidents/${id}/assign`, {
      method: 'PATCH',
      body: JSON.stringify({ assigned_analyst }),
    }),
  addIncidentNote: (id: string, payload: { note_text: string }) =>
    request<{ status: string; note_id: number }>(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  executeResponseAction: (id: string, payload: { action_type: string; target: string; details?: string; ttl_hours?: number }) =>
    request<{ status: string; action_status: string; is_simulated: boolean; blocklist_entry_id: number | null; message: string }>(`/incidents/${id}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  runCorrelationCycle: () =>
    request<{ status: string; correlations_created: number; details: any[] }>('/incidents/correlate', {
      method: 'POST',
    }),
  exportIncidentReportText: (id: string): Promise<string> => requestText(`/incidents/${id}/export?format=text`),

  // Forensics
  getForensics: (id: string) => request<ForensicInvestigation>(`/forensics/${id}`),

  // Events Stream & Acknowledgment
  getEvents: (params?: { severity?: string; source?: string; search?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.severity && params.severity !== 'All') query.set('severity', params.severity);
    if (params?.source && params.source !== 'All') query.set('source', params.source);
    if (params?.search) query.set('search', params.search);
    if (params?.limit) query.set('limit', String(params.limit));
    return request<SecurityEvent[]>(`/events?${query.toString()}`);
  },
  acknowledgeEvent: (eventId: string, acknowledgedBy: string) =>
    request<{ status: string; message: string }>(`/events/${eventId}/acknowledge`, {
      method: 'PATCH',
      body: JSON.stringify({ acknowledged_by: acknowledgedBy }),
    }),

  // System & Seed
  getSystemStatus: () => request<SystemStatusData>('/system/status'),
  seedOrResetDemoData: (forceReset: boolean = false) =>
    request<{ status: string; message: string }>(`/system/seed-demo?force_reset=${forceReset}`, {
      method: 'POST',
    }),
};
