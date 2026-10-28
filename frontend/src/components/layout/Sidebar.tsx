import React, { useState } from 'react';
import {
  LayoutDashboard, Users, Activity, ShieldAlert, KeyRound,
  AlertTriangle, Fingerprint, BarChart3, Bell, Settings,
  Globe, UserCheck, ShieldCheck, ChevronDown, ChevronRight,
  Radio, FileSearch, Network, MailWarning, FileText
} from 'lucide-react';
import { UserRole } from '../../types';

export type NavTab =
  | 'overview'
  | 'dashboard'
  | 'employees'
  | 'monitoring'
  | 'monitoring_web'
  | 'monitoring_email'
  | 'monitoring_file'
  | 'threats'
  | 'threats_phishing'
  | 'threats_url'
  | 'threats_files'
  | 'threats_network'
  | 'secrets'
  | 'dlp'
  | 'incidents'
  | 'incident_detail'
  | 'soc_analyst'
  | 'forensics'
  | 'employee_dashboard'
  | 'employee_portal'
  | 'url_warning'
  | 'reports'
  | 'notifications'
  | 'blocklist'
  | 'zetaris'
  | 'administration'
  | 'soc_ops'
  | 'admin_overview'
  | 'settings'
  | 'system';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  openIncidentsCount: number;
  userRole?: UserRole;
  userName?: string;
  onLogout?: () => void;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  openIncidentsCount,
  userRole = 'Super Admin',
  userName = 'Admin',
  isOpenMobile = false,
  onCloseMobile,
}) => {
  const isEmployee = userRole === 'Employee';
  const staff = !isEmployee;
  const isAdmin = userRole === 'Super Admin' || userRole === 'Security Administrator';
  const [monitoringExpanded, setMonitoringExpanded] = useState(true);
  const [threatsExpanded, setThreatsExpanded] = useState(true);

  const isTabActive = (tab: NavTab) => {
    if (currentTab === tab) return true;
    if (tab === 'incidents' && (currentTab === 'soc_analyst' || currentTab === 'incident_detail')) return true;
    if (tab === 'overview' && currentTab === 'dashboard') return true;
    if (tab === 'secrets' && currentTab === 'dlp') return true;
    if (tab === 'employee_dashboard' && currentTab === 'employee_portal') return true;
    if (tab === 'monitoring' && currentTab.startsWith('monitoring_')) return true;
    if (tab === 'threats' && currentTab.startsWith('threats_')) return true;
    return false;
  };

  const handleNav = (tab: NavTab) => {
    onSelectTab(tab);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/50 backdrop-blur-xs md:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed md:sticky top-0 left-0 z-40 h-screen w-64 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 flex flex-col justify-between transition-all duration-200 border-r border-slate-200 dark:border-slate-800 ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 overflow-y-auto">
          {/* Logo Section */}
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-600 flex items-center justify-center text-white font-bold text-sm shadow-sm">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-1.5">
                CYBERSHIELD <span className="text-sky-600 dark:text-sky-400">AI</span>
              </h2>
              <p className="text-[10px] text-slate-400 dark:text-slate-400 font-medium">Enterprise SOC & 24/7 Monitoring</p>
            </div>
          </div>

          {/* Navigation Menu Matching User's Exact Mockup */}
          <div className="p-3 space-y-1">
            {isAdmin && (
              <button
                onClick={() => handleNav('admin_overview')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'admin_overview'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <ShieldCheck className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Admin Overview</span>
              </button>
            )}

            {/* 1. Overview (Dashboard) */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('overview')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'overview'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <LayoutDashboard className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>Overview</span>
            </button>

            </>
            )}

            {/* 2. Employees */}
            {(userRole === 'Super Admin' || userRole === 'Security Administrator') && (
              <button
                onClick={() => handleNav('employees')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'employees'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Users className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Employees</span>
              </button>
            )}

            {/* 3. Monitoring Center (Expandable) */}
            {staff && (
            <>
            <div>
              <button
                onClick={() => {
                  setMonitoringExpanded(!monitoringExpanded);
                  handleNav('monitoring_web');
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                  isTabActive('monitoring')
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Activity className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                  <span>Monitoring Center</span>
                </div>
                {monitoringExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                )}
              </button>

              {monitoringExpanded && (
                <div className="pl-9 pr-2 py-1 space-y-1 text-xs">
                  <button
                    onClick={() => handleNav('monitoring_web')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'monitoring_web'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • Web Activity
                  </button>
                  <button
                    onClick={() => handleNav('monitoring_email')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'monitoring_email'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • Email Security
                  </button>
                  <button
                    onClick={() => handleNav('monitoring_file')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'monitoring_file'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • File & Data Monitoring
                  </button>
                  <button
                    onClick={() => handleNav('monitoring')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'monitoring'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • 24/7 Telemetry Feeds
                  </button>
                </div>
              )}
            </div>

            </>
            )}

            {/* 4. Threat Detection (Expandable) */}
            {staff && (
            <>
            <div>
              <button
                onClick={() => {
                  setThreatsExpanded(!threatsExpanded);
                  handleNav('threats_phishing');
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                  isTabActive('threats')
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <ShieldAlert className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                  <span>Threat Detection</span>
                </div>
                {threatsExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                )}
              </button>

              {threatsExpanded && (
                <div className="pl-9 pr-2 py-1 space-y-1 text-xs">
                  <button
                    onClick={() => handleNav('threats_phishing')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'threats_phishing'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • Phishing Email
                  </button>
                  <button
                    onClick={() => handleNav('threats_url')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'threats_url'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • URL Scanner
                  </button>
                  <button
                    onClick={() => handleNav('threats_files')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'threats_files'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • File Analysis
                  </button>
                  <button
                    onClick={() => handleNav('threats_network')}
                    className={`w-full text-left py-1.5 px-2 rounded transition ${
                      currentTab === 'threats_network'
                        ? 'text-sky-600 dark:text-sky-400 font-semibold bg-sky-50/60 dark:bg-sky-950/40'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    • Network Anomalies
                  </button>
                </div>
              )}
            </div>

            </>
            )}

            {staff && (
              <button
                onClick={() => handleNav('soc_ops')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'soc_ops'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Activity className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>SOC Operations</span>
              </button>
            )}

            {/* 5. Secret Detection (Screen 6) */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('secrets')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'secrets'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <div className="flex items-center gap-3">
                <KeyRound className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Secret Detection</span>
              </div>
              <span className="text-[10px] bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 px-1.5 py-0.5 rounded-full font-bold">
                DLP
              </span>
            </button>

            </>
            )}

            {/* 6. Threat Alerts / Incidents (Screen 10) */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('incidents')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'incidents' || currentTab === 'incident_detail'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Incident Management</span>
              </div>
              {openIncidentsCount > 0 && (
                <span className="text-[10px] bg-red-500 text-white font-bold px-1.5 py-0.2 rounded-full">
                  {openIncidentsCount}
                </span>
              )}
            </button>

            </>
            )}

            {/* 8. Digital Forensics */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('forensics')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'forensics'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Fingerprint className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>Digital Forensics</span>
            </button>

            </>
            )}

            {/* 9. Employee Dashboard (Screen 9) */}
            {isEmployee && (
            <>
            <button
              onClick={() => handleNav('employee_dashboard')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'employee_dashboard'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <ShieldCheck className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>My Dashboard</span>
            </button>

            </>
            )}

            {/* 10. URL Warning Page (Screen 7) */}
            <button
              onClick={() => handleNav('url_warning')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'url_warning'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Globe className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>URL Warning Page</span>
            </button>

            {/* 11. Reports & Analytics (Screen 11) */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('reports')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'reports'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <BarChart3 className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>Reports</span>
            </button>

            {staff && (
              <button
                onClick={() => handleNav('zetaris')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'zetaris'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Network className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Data Sources (Zetaris)</span>
              </button>
            )}

            </>
            )}

            {/* Blocklist: the prevention control. Staff only. */}
            {staff && (
              <button
                onClick={() => handleNav('blocklist')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'blocklist'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <ShieldAlert className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Blocklist</span>
              </button>
            )}

            {/* 12. Notifications (Screen 12) */}
            {staff && (
            <>
            <button
              onClick={() => handleNav('notifications')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'notifications'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Bell className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>Notifications</span>
            </button>

            </>
            )}

            {isAdmin && (
              <button
                onClick={() => handleNav('administration')}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                  currentTab === 'administration'
                    ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <ShieldCheck className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                <span>Administration</span>
              </button>
            )}

            {/* 13. Settings (Screen 13) */}
            <button
              onClick={() => handleNav('settings')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition ${
                currentTab === 'settings'
                  ? 'bg-sky-50 dark:bg-sky-600/20 text-sky-700 dark:text-sky-300 font-semibold'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Settings className="w-4 h-4 text-slate-500 dark:text-slate-400" />
              <span>Settings</span>
            </button>
          </div>
        </div>

        {/* Footer: User Role Badge */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">Security Scope</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-sky-100 dark:bg-sky-950 text-sky-700 dark:text-sky-300">
              {userRole}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};
