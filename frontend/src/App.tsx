import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { EmployeeManagementPage } from './pages/EmployeeManagementPage';
import { MonitoringCenterPage } from './pages/MonitoringCenterPage';
import { MonitoringSourcesPage } from './pages/MonitoringSourcesPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { DLPPage } from './pages/DLPPage';
import { URLWarningModal } from './pages/URLWarningModal';
import { IncidentResponsePage } from './pages/IncidentResponsePage';
import { EmployeeDashboardPage } from './pages/EmployeeDashboardPage';
import { IncidentsListPage } from './pages/IncidentsListPage';
import { ReportsPage } from './pages/ReportsPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ForensicsPage } from './pages/ForensicsPage';
import { FileAnalysisPage } from './pages/FileAnalysisPage';
import { NetworkAnomalyPage } from './pages/NetworkAnomalyPage';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { ProfileSettingsModal } from './components/profile/ProfileSettingsModal';
import { api, UNAUTHORIZED_EVENT } from './api/client';
import { BlocklistPage } from './pages/BlocklistPage';
import { DashboardMetrics, SessionState, UserSession } from './types';

export function App() {
  const [currentUser, setCurrentUser] = useState<UserSession | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);

  // A session that exists but still owes MFA or a password change; shown on the sign-in screen.
  const [pendingSession, setPendingSession] = useState<SessionState | null>(null);

  const landingTab = (user: UserSession): NavTab => (user.role === 'Employee' ? 'employee_dashboard' : 'overview');

  const applySession = (state: SessionState | null) => {
    if (state && state.mfa_state === 'ok' && !state.must_change_password) {
      setPendingSession(null);
      setCurrentUser(state.user);
      setCurrentTab(landingTab(state.user));
    } else {
      setCurrentUser(null);
      setPendingSession(state);
    }
  };

  // The session lives in an HttpOnly cookie; ask the server whether we still have one.
  useEffect(() => {
    api.getMe().then(applySession).catch(() => applySession(null)).finally(() => setAuthChecking(false));
  }, []);

  // Any 401 elsewhere in the app means the session ended: return to sign-in.
  useEffect(() => {
    const onUnauthorized = () => { setCurrentUser(null); setPendingSession(null); };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const fetchGlobalMetrics = async () => {
    try {
      const data = await api.getDashboardMetrics();
      setMetrics(data);
    } catch (e) {
      console.error('Failed to load metrics:', e);
    }
  };

  useEffect(() => {
    if (currentUser) {
      fetchGlobalMetrics();
      const interval = setInterval(fetchGlobalMetrics, 30000);
      return () => clearInterval(interval);
    }
  }, [currentUser]);

  const handleLoginSuccess = (user: UserSession) => {
    setPendingSession(null);
    setCurrentUser(user);
    setCurrentTab(landingTab(user));
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (err) {
      console.warn('Logout API warning:', err);
    } finally {
      setCurrentUser(null);
      setPendingSession(null);
      setCurrentTab('overview');
    }
  };

  const handleSelectIncidentFromStream = (id: string) => {
    setSelectedIncidentId(id);
    setCurrentTab('soc_analyst');
  };

  const handleNavigateToForensics = (id: string) => {
    setSelectedIncidentId(id);
    setCurrentTab('forensics');
  };

  // Smart global search handler for header
  const handleGlobalSearch = (query: string) => {
    const q = query.toLowerCase().trim();
    if (!q) return;
    if (q.includes('phish') || q.includes('mail')) {
      setCurrentTab('threats_phishing');
    } else if (q.includes('url') || q.includes('web') || q.includes('browser')) {
      setCurrentTab('monitoring_web');
    } else if (q.includes('emp') || q.includes('user') || q.includes('staff')) {
      setCurrentTab('employees');
    } else if (q.includes('secret') || q.includes('dlp') || q.includes('token') || q.includes('key')) {
      setCurrentTab('secrets');
    } else if (q.includes('inc') || q.includes('alert')) {
      setCurrentTab('incidents');
    } else if (q.includes('rep') || q.includes('audit')) {
      setCurrentTab('reports');
    } else if (q.includes('notif') || q.includes('sms')) {
      setCurrentTab('notifications');
    } else if (q.includes('set') || q.includes('config')) {
      setCurrentTab('settings');
    } else if (q.includes('forensic')) {
      setCurrentTab('forensics');
    }
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-white">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin mb-3" />
        <p className="text-xs font-mono text-slate-400">Verifying CYBERSHIELD Enterprise Security Session...</p>
      </div>
    );
  }

  // If user is not authenticated, render LoginPage (Screen 1)
  if (!currentUser) {
    return <LoginPage resume={pendingSession} onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col font-sans text-slate-900 dark:text-slate-100 antialiased transition-colors duration-200">
      <div className="flex flex-1 relative">
        {/* Modern Themed SOC Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          openIncidentsCount={metrics?.open_investigations ?? 0}
          userRole={currentUser.role}
          userName={currentUser.name}
          onLogout={handleLogout}
          isOpenMobile={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
        />

        {/* Main Operational Stage */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {/* SOC Top Navigation Header with Light/Dark Switcher */}
          <Header
            currentUser={currentUser}
            openInvestigationsCount={metrics?.open_investigations ?? 0}
            onLogout={handleLogout}
            onToggleSidebar={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
            onSearch={handleGlobalSearch}
            onOpenProfileSettings={() => setIsProfileModalOpen(true)}
          />

          {/* Active View Content (13 Mockup Screens) */}
          <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto bg-slate-50 dark:bg-slate-950 transition-colors">
            {/* Screen 2: Dashboard (SOC / Admin) */}
            {(currentTab === 'overview' || currentTab === 'dashboard') && (
              <DashboardPage
                onNavigateToTab={setCurrentTab}
                onSelectIncident={handleSelectIncidentFromStream}
              />
            )}

            {/* Screen 3: Employee Management */}
            {currentTab === 'employees' && <EmployeeManagementPage />}

            {/* Screen 4: Monitoring Center (Web Activity, Email, Files, Sources) */}
            {currentTab === 'monitoring_web' && <MonitoringCenterPage initialSubTab="web" />}
            {currentTab === 'monitoring_email' && <MonitoringCenterPage initialSubTab="email" />}
            {currentTab === 'monitoring_file' && <MonitoringCenterPage initialSubTab="files" />}
            {currentTab === 'monitoring' && <MonitoringCenterPage initialSubTab="sources" />}

            {/* Screen 5: Threat Detection (Phishing Email, URL Scanner, File, Network) */}
            {currentTab === 'threats_phishing' && <ThreatDetectionPage initialSubTab="phishing" />}
            {currentTab === 'threats_url' && <ThreatDetectionPage initialSubTab="url" />}
            {currentTab === 'threats_files' && <FileAnalysisPage />}
            {currentTab === 'threats_network' && <NetworkAnomalyPage />}
            {currentTab === 'threats' && <ThreatDetectionPage initialSubTab="phishing" />}

            {/* Screen 6: Secret Detection (DLP) */}
            {(currentTab === 'secrets' || currentTab === 'dlp') && <DLPPage />}

            {/* Screen 7: URL Warning Page (Employee View) */}
            {currentTab === 'url_warning' && (
              <URLWarningModal
                employeeEmail={currentUser.email}
                onSafeReturn={() => setCurrentTab('overview')}
                onClose={() => setCurrentTab('overview')}
              />
            )}

            {/* Screen 8: SOC Analyst - Incident Detail */}
            {(currentTab === 'soc_analyst' || currentTab === 'incident_detail') && (
              <IncidentResponsePage
                selectedIncidentId={selectedIncidentId}
                onNavigateToForensics={handleNavigateToForensics}
              />
            )}

            {/* Screen 9: Employee Dashboard (Personalized for Rahul Kumar / Employee) */}
            {(currentTab === 'employee_dashboard' || currentTab === 'employee_portal') && (
              <EmployeeDashboardPage
                currentUser={currentUser}
                onNavigateToTab={setCurrentTab}
              />
            )}

            {/* Screen 10: Incidents List */}
            {currentTab === 'incidents' && (
              <IncidentsListPage
                onSelectIncident={handleSelectIncidentFromStream}
              />
            )}

            {/* Screen 11: Reports & Analytics */}
            {currentTab === 'reports' && <ReportsPage />}

            {/* Screen 12: Notifications */}
            {currentTab === 'notifications' && <NotificationsPage />}

            {/* Screen 13: Settings */}
            {currentTab === 'settings' && (
              <SettingsPage
                currentUser={currentUser}
                onUpdateUser={setCurrentUser}
              />
            )}

            {/* Digital Forensics Page */}
            {currentTab === 'forensics' && (
              <ForensicsPage initialIncidentId={selectedIncidentId} />
            )}

            {/* Blocklist: proposals, approvals and firewall feeds */}
            {currentTab === 'blocklist' && <BlocklistPage currentUser={currentUser} />}

            {/* System Status Diagnostic Page */}
            {currentTab === 'system' && <SystemStatusPage />}
          </main>
        </div>
      </div>

      {/* Global User Profile Settings Modal */}
      {currentUser && (
        <ProfileSettingsModal
          isOpen={isProfileModalOpen}
          onClose={() => setIsProfileModalOpen(false)}
          currentUser={currentUser}
          onUpdateUser={setCurrentUser}
        />
      )}
    </div>
  );
}

export default App;

