import {
  DashboardMetrics, ThreatSeverityDistribution, ActivityDataPoint,
  SecurityEvent, PhishingAnalysisResult, FileAnalysisResult,
  NetworkAnalysisBatchResult, IncidentDetail, ForensicInvestigation,
  SystemStatusData, UserSession, DemoAccount, Employee, MonitoringSource,
  SecretFinding, NotificationDelivery, URLInspectionResult
} from '../types';

const BASE_URL = (import.meta.env.VITE_API_URL as string) || '/api/v1';

let authToken: string | null = localStorage.getItem('cybershield_token');

export const setAuthToken = (token: string | null) => {
  authToken = token;
  if (token) {
    localStorage.setItem('cybershield_token', token);
  } else {
    localStorage.removeItem('cybershield_token');
  }
};

export const getAuthToken = () => authToken;

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const errorText = await res.text();
    let errorMsg = `API Error ${res.status}: ${res.statusText}`;
    try {
      const parsed = JSON.parse(errorText);
      if (parsed.detail) errorMsg = parsed.detail;
    } catch {
      if (errorText) errorMsg = errorText;
    }
    throw new Error(errorMsg);
  }

  return res.json() as Promise<T>;
}

export const api = {
  // Authentication & RBAC
  login: async (credentials: { email: string; password: string }): Promise<UserSession> => {
    const res = await request<any>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    const user = res.user || res;
    return {
      id: user.id,
      email: user.email,
      name: user.full_name || user.name,
      role: user.role,
      department: user.department || 'Security Operations',
      is_active: user.is_active,
      access_token: res.access_token,
    };
  },
  loginWithSSO: async (payload: { provider: 'google' | 'microsoft'; email: string; name?: string; role?: string }): Promise<UserSession> => {
    const res = await request<any>('/auth/sso', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const user = res.user || res;
    return {
      id: user.id,
      email: user.email,
      name: user.full_name || user.name,
      role: user.role,
      department: user.department || 'Corporate Workspace',
      is_active: user.is_active,
      access_token: res.access_token,
    };
  },
  getMe: async (): Promise<UserSession> => {
    const res = await request<any>('/auth/me');
    return {
      id: res.id,
      email: res.email,
      name: res.full_name || res.name,
      role: res.role,
      department: res.department || 'Security Operations',
      is_active: res.is_active,
      access_token: getAuthToken() || '',
    };
  },
  updateProfile: async (payload: { full_name?: string; department?: string; phone_number?: string }): Promise<UserSession> => {
    const res = await request<any>('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    return {
      id: res.id,
      email: res.email,
      name: res.full_name || res.name,
      role: res.role,
      department: res.department || 'Security Operations',
      is_active: res.is_active,
      access_token: getAuthToken() || '',
    };
  },
  changePassword: (payload: { current_password?: string; new_password: string }) =>
    request<{ status: string; message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  logout: () =>
    request<{ status: string; message: string }>('/auth/logout', {
      method: 'POST',
    }),
  resetPassword: (payload: { email: string; new_password?: string }) =>
    request<{ status: string; message: string }>('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getDemoAccounts: () => request<DemoAccount[]>('/auth/demo-accounts'),

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
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const res = await fetch(`${BASE_URL}/files/analyze`, {
      method: 'POST',
      headers,
      body: formData,
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(err || 'File analysis failed');
    }
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
  addIncidentNote: (id: string, payload: { analyst_name: string; note_text: string }) =>
    request<{ status: string; note_id: number }>(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  executeResponseAction: (id: string, payload: { action_type: string; target: string; details?: string }) =>
    request<{ status: string; is_simulated: boolean; message: string }>(`/incidents/${id}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  runCorrelationCycle: () =>
    request<{ status: string; correlations_created: number; details: any[] }>('/incidents/correlate', {
      method: 'POST',
    }),
  exportIncidentReportText: async (id: string): Promise<string> => {
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const res = await fetch(`${BASE_URL}/incidents/${id}/export?format=text`, { headers });
    if (!res.ok) throw new Error('Report export failed');
    return res.text();
  },

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
