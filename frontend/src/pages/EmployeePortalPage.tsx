import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, AlertTriangle, Mail, Send, CheckCircle2, Lock,
  FileWarning, HelpCircle, Bell, ArrowRight, UserCheck, ShieldAlert,
  ThumbsUp, ExternalLink, RefreshCw
} from 'lucide-react';
import { api } from '../api/client';
import { NotificationDelivery, PhishingAnalysisResult, UserSession } from '../types';

interface EmployeePortalPageProps {
  currentUser?: UserSession | null;
}

export const EmployeePortalPage: React.FC<EmployeePortalPageProps> = ({ currentUser }) => {
  const [notifications, setNotifications] = useState<NotificationDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [acknowledgedIds, setAcknowledgedIds] = useState<Set<string>>(new Set());

  // Report Suspicious Email / URL state
  const [reportType, setReportType] = useState<'email' | 'url'>('email');
  const [reportContent, setReportContent] = useState('');
  const [reportSubject, setReportSubject] = useState('');
  const [reportSender, setReportSender] = useState('');
  const [submittingReport, setSubmittingReport] = useState(false);
  const [reportResult, setReportResult] = useState<PhishingAnalysisResult | null>(null);

  const employeeEmail = currentUser?.email || 'alex.turner@enterprise-corp.com';
  const employeeName = currentUser?.name || 'Alex Turner';

  const loadNotifications = async () => {
    setLoading(true);
    try {
      const data = await api.getNotificationDeliveries({ recipient_type: 'EMPLOYEE', limit: 20 });
      setNotifications(data);
    } catch (err) {
      console.error('Failed to load employee notifications:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotifications();
  }, []);

  const handleAcknowledge = (deliveryId: string) => {
    setAcknowledgedIds((prev) => new Set(prev).add(deliveryId));
  };

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportContent.trim()) return;
    setSubmittingReport(true);
    setReportResult(null);

    try {
      const res = await api.analyzePhishing({
        submission_type: reportType,
        content: reportContent.trim(),
        email_subject: reportSubject.trim() || undefined,
        sender_info: reportSender.trim() || undefined,
      });
      setReportResult(res);
      // Refresh notifications as a delivery might have been dispatched
      loadNotifications();
    } catch (err: any) {
      alert(`Report submission failed: ${err.message}`);
    } finally {
      setSubmittingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Personalized Welcome Header */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Employee Security Portal
            </h1>
            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Personalized Security Feed
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Welcome back, <span className="font-semibold text-slate-700">{employeeName}</span> ({employeeEmail}).
            Review corporate security advisories and report potential threats to the SOC team.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadNotifications}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Feed</span>
          </button>
        </div>
      </div>

      {/* Security Hygiene & Policy Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0 border border-emerald-200">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-500 font-medium">Security Posture</div>
            <div className="text-lg font-bold text-slate-900">Compliant & Secure</div>
            <p className="text-[11px] text-emerald-600 mt-0.5">Zero active security policy violations</p>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-sky-50 text-sky-600 flex items-center justify-center shrink-0 border border-sky-200">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-500 font-medium">Assigned Policy</div>
            <div className="text-lg font-bold text-slate-900">Standard Telemetry</div>
            <p className="text-[11px] text-slate-500 mt-0.5">Email gateway & web intercept active</p>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center shrink-0 border border-indigo-200">
            <Bell className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-500 font-medium">Security Advisories</div>
            <div className="text-lg font-bold text-slate-900">{notifications.length} Dispatched</div>
            <p className="text-[11px] text-slate-500 mt-0.5">Recent targeted notifications</p>
          </div>
        </div>
      </div>

      {/* Main Grid: Report Suspicious Content & Notification Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Report Phishing / Malicious Item (5 cols) */}
        <div className="lg:col-span-5 bg-white p-6 rounded-xl border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Mail className="w-5 h-5 text-sky-600" />
              <h2 className="text-sm font-bold text-slate-900">
                Report Suspicious Email or Link
              </h2>
            </div>
            <p className="text-xs text-slate-500 mb-4">
              Suspect an email or message is phishing or social engineering? Forward details directly to the SOC AI engine.
            </p>

            <form onSubmit={handleReportSubmit} className="space-y-3">
              <div className="flex items-center gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setReportType('email')}
                  className={`flex-1 py-1.5 rounded-lg border font-semibold transition ${
                    reportType === 'email'
                      ? 'bg-sky-50 border-sky-400 text-sky-700'
                      : 'bg-slate-50 border-slate-200 text-slate-600'
                  }`}
                >
                  Phishing Email
                </button>
                <button
                  type="button"
                  onClick={() => setReportType('url')}
                  className={`flex-1 py-1.5 rounded-lg border font-semibold transition ${
                    reportType === 'url'
                      ? 'bg-sky-50 border-sky-400 text-sky-700'
                      : 'bg-slate-50 border-slate-200 text-slate-600'
                  }`}
                >
                  Suspicious URL
                </button>
              </div>

              {reportType === 'email' && (
                <>
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                      Subject Line
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Urgent: Account Verification Required"
                      value={reportSubject}
                      onChange={(e) => setReportSubject(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded focus:ring-1 focus:ring-sky-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                      Sender Email / Info
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. security-team@external-unknown.com"
                      value={reportSender}
                      onChange={(e) => setReportSender(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded focus:ring-1 focus:ring-sky-500"
                    />
                  </div>
                </>
              )}

              <div>
                <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                  {reportType === 'email' ? 'Email Body or Raw Headers *' : 'Target URL *'}
                </label>
                <textarea
                  rows={4}
                  required
                  placeholder={
                    reportType === 'email'
                      ? 'Paste the suspicious email text, call to action, or link...'
                      : 'https://suspicious-domain-verify.com/login'
                  }
                  value={reportContent}
                  onChange={(e) => setReportContent(e.target.value)}
                  className="w-full font-mono text-xs p-2.5 bg-slate-50 border border-slate-300 rounded focus:ring-1 focus:ring-sky-500"
                />
              </div>

              <button
                type="submit"
                disabled={submittingReport || !reportContent.trim()}
                className="w-full py-2 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 text-white font-semibold text-xs shadow-xs transition flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{submittingReport ? 'Analyzing & Notifying SOC...' : 'Submit to SOC Operations'}</span>
              </button>
            </form>
          </div>

          {/* Report Feedback Display */}
          {reportResult && (
            <div className="mt-4 p-3.5 rounded-xl border border-sky-200 bg-sky-50 text-xs">
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sky-900">Analysis Verdict: {reportResult.risk_category}</span>
                <span className="text-[11px] font-mono text-sky-700">Risk Score: {reportResult.risk_score}/100</span>
              </div>
              <p className="text-slate-700 text-[11px] mb-2">{reportResult.explanation}</p>
              <div className="text-[11px] text-emerald-800 font-medium flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                <span>Report ticket sent to SOC Tier-1 Analysts. Thank you for your vigilance!</span>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Security Advisories & Required Actions (7 cols) */}
        <div className="lg:col-span-7 bg-white p-6 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <div className="flex items-center gap-2">
              <FileWarning className="w-5 h-5 text-amber-500" />
              <div>
                <h2 className="text-sm font-bold text-slate-900">Security Advisories & Warnings</h2>
                <p className="text-[11px] text-slate-500">Targeted security notices sent to your employee profile</p>
              </div>
            </div>
            <span className="text-xs text-slate-400">{notifications.length} alerts</span>
          </div>

          <div className="space-y-3">
            {loading ? (
              <div className="py-12 text-center text-xs text-slate-500">
                <div className="w-5 h-5 border-2 border-sky-600 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                <span>Loading your personal security advisories...</span>
              </div>
            ) : notifications.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500 bg-slate-50 rounded-xl">
                No active security warnings or advisories for your account. You're all clear!
              </div>
            ) : (
              notifications.map((notif) => {
                const isAck = acknowledgedIds.has(notif.delivery_id);
                return (
                  <div
                    key={notif.delivery_id}
                    className={`p-4 rounded-xl border transition ${
                      isAck ? 'bg-slate-50/60 border-slate-200 opacity-80' : 'bg-white border-slate-200 shadow-xs'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          notif.severity === 'Critical' ? 'bg-red-100 text-red-800' :
                          notif.severity === 'High' ? 'bg-amber-100 text-amber-800' : 'bg-sky-100 text-sky-800'
                        }`}>
                          {notif.severity}
                        </span>
                        <h3 className="text-xs font-bold text-slate-900">{notif.title}</h3>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {new Date(notif.sent_at).toLocaleDateString()}
                      </span>
                    </div>

                    <p className="text-xs text-slate-600 leading-relaxed mb-3">
                      {notif.body_preview}
                    </p>

                    <div className="flex items-center justify-between pt-2 border-t border-slate-100 text-[11px]">
                      <span className="text-slate-400">
                        Via: <span className="font-semibold text-slate-600">{notif.channel}</span> ({notif.recipient_address})
                      </span>

                      {isAck ? (
                        <span className="inline-flex items-center gap-1 text-emerald-600 font-semibold text-xs">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Acknowledged</span>
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleAcknowledge(notif.delivery_id)}
                          className="px-3 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs transition"
                        >
                          Acknowledge & Mark Read
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
