import React, { useEffect, useState } from 'react';
import {
  ShieldCheck, AlertTriangle, Globe, Bell, CheckCircle2,
  ExternalLink, Mail, Send, Lock, ArrowRight, ShieldAlert,
  ThumbsUp, Shield
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { api } from '../api/client';
import { UserSession } from '../types';

interface Props {
  currentUser?: UserSession | null;
  onNavigateToTab?: (tab: any) => void;
}

export const EmployeeDashboardPage: React.FC<Props> = ({ currentUser, onNavigateToTab }) => {
  const { theme } = useTheme();
  const employeeName = currentUser?.name ?? '';
  const employeeEmail = currentUser?.email ?? '';

  const [reportType, setReportType] = useState<'email' | 'url'>('email');
  const [reportContent, setReportContent] = useState('');
  const [submittingReport, setSubmittingReport] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  // The employee's own alerts, from the server. Nothing is invented when there are none or the call fails.
  const [recentAlerts, setRecentAlerts] = useState<{ id: string; time: string; alert: string; risk: string }[]>([]);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    const id = currentUser?.employee_id;
    if (!id) return;
    api.getEmployeeEvents(id)
      .then((events) => setRecentAlerts(events.slice(0, 8).map((e) => ({
        id: e.event_id, alert: e.threat_category, risk: e.severity,
        time: new Date(/[zZ]$/.test(e.timestamp) ? e.timestamp : e.timestamp + 'Z').toLocaleString(),
      }))))
      .catch((e) => setAlertsError(e.message));
  }, [currentUser?.employee_id]);

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportContent.trim()) return;
    setSubmittingReport(true);
    try {
      await api.analyzePhishing({
        submission_type: reportType,
        content: reportContent.trim(),
      });
      setReportSuccess(true);
      setReportError(null);
      setReportContent('');
    } catch (err: any) {
      setReportSuccess(false);
      setReportError(err.message || 'Your report could not be sent. Please try again.');   // never claim success on failure
    } finally {
      setSubmittingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Welcome Header matching Screen 9 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Welcome, {employeeName}
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Here is your security activity and notifications.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700">
            {employeeEmail}
          </span>
        </div>
      </div>

      {/* 4 KPI Cards matching Screen 9 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Card 1: Security Alerts */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
            <Bell className="w-6 h-6" />
          </div>
          <div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Security Alerts</div>
            <div className="text-2xl font-bold text-slate-900 dark:text-white">{recentAlerts.length}</div>
          </div>
        </div>

        {/* Card 2: Suspicious URLs */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Suspicious URLs</div>
            <div className="text-2xl font-bold text-slate-900 dark:text-white">{recentAlerts.filter((a) => /url|phish|domain|link|site/i.test(a.alert)).length}</div>
          </div>
        </div>

        {/* Card 3: Action Required */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Action Required</div>
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">{recentAlerts.filter((a) => a.risk === 'High' || a.risk === 'Critical').length}</div>
          </div>
        </div>

        {/* Card 4: Status Active */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Status</div>
            <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400">{currentUser?.is_active ? 'Active' : 'Inactive'}</div>
          </div>
        </div>
      </div>

      {/* Main Row: Recent Alerts (Left) & Security Tips (Right) matching Screen 9 */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Recent Alerts (7 cols) */}
        <div className="lg:col-span-7 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden flex flex-col justify-between">
          <div>
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Recent Alerts</h3>
              <button
                onClick={() => onNavigateToTab && onNavigateToTab('notifications')}
                className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline"
              >
                View All
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold text-[11px]">
                    <th className="py-2.5 px-4">Time</th>
                    <th className="py-2.5 px-4">Alert Description</th>
                    <th className="py-2.5 px-4 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {recentAlerts.length === 0 && (
                    <tr><td colSpan={3} className="py-6 px-4 text-center text-xs text-slate-500">{alertsError ?? 'No alerts for you right now.'}</td></tr>
                  )}
                  {recentAlerts.map((alt) => (
                    <tr key={alt.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono text-slate-500 dark:text-slate-400">{alt.time}</td>
                      <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{alt.alert}</td>
                      <td className="py-3 px-4 text-right">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          alt.risk === 'High' ? 'bg-amber-50 dark:bg-amber-950 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900' :
                          alt.risk === 'Medium' ? 'bg-yellow-50 dark:bg-yellow-950 text-yellow-600 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900' :
                          'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-900'
                        }`}>
                          {alt.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Quick Report Tool */}
          <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-800">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5 text-sky-600" />
              <span>Report Suspicious Email or Link to SOC</span>
            </h4>
            <form onSubmit={handleReportSubmit} className="flex gap-2">
              <input
                type="text"
                required
                placeholder="Paste suspicious link or email subject..."
                value={reportContent}
                onChange={(e) => setReportContent(e.target.value)}
                className="flex-1 px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
              />
              <button
                type="submit"
                disabled={submittingReport || !reportContent.trim()}
                className="px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shrink-0"
              >
                {submittingReport ? 'Sending...' : 'Report'}
              </button>
            </form>
            {reportError && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{reportError}</p>}
            {reportSuccess && (
              <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-semibold mt-1">
                ✓ Report delivered to SOC Analyst team. Thank you!
              </p>
            )}
          </div>
        </div>

        {/* Security Tips (5 cols) matching Screen 9 */}
        <div className="lg:col-span-5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800 mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Security Tips</h3>
              <span className="text-xs text-sky-600 dark:text-sky-400 font-semibold cursor-pointer hover:underline">
                See All
              </span>
            </div>

            <div className="space-y-3.5 text-xs">
              {/* Tip 1 */}
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                <div className="font-semibold text-slate-900 dark:text-white mb-0.5">
                  Be careful with unknown links
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                  Avoid clicking on suspicious links from unknown sources.
                </p>
              </div>

              {/* Tip 2 */}
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                <div className="font-semibold text-slate-900 dark:text-white mb-0.5">
                  Verify sender identity
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                  Always check the sender's email address and domain spelling.
                </p>
              </div>

              {/* Tip 3 */}
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                <div className="font-semibold text-slate-900 dark:text-white mb-0.5">
                  Report suspicious activity
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                  If you notice anything unusual, report it immediately to the IT SOC team.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Corporate Compliance Guard</span>
            <span className="text-emerald-600 font-semibold">Active</span>
          </div>
        </div>
      </div>
    </div>
  );
};
