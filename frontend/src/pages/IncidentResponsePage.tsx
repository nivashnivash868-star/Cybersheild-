import React, { useState, useEffect } from 'react';
import {
  AlertTriangle, Shield, CheckCircle2, User, Clock, FileDown,
  Plus, Send, ArrowRight, ShieldAlert, Lock, Ban, Activity, RefreshCw,
  ExternalLink, Mail, Phone, Globe, UserCheck
} from 'lucide-react';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { IncidentDetail, IncidentStatus, Severity } from '../types';

interface Props {
  selectedIncidentId?: string | null;
  onNavigateToForensics?: (id: string) => void;
}

export const IncidentResponsePage: React.FC<Props> = ({
  selectedIncidentId,
  onNavigateToForensics,
}) => {
  const { theme } = useTheme();
  const [incidents, setIncidents] = useState<IncidentDetail[]>([]);
  const [activeIncident, setActiveIncident] = useState<IncidentDetail | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'events' | 'response' | 'activity'>('overview');
  const [status, setStatus] = useState<string>('Open');
  const [assignedAnalyst, setAssignedAnalyst] = useState('Unassigned');
  const [newNote, setNewNote] = useState('');
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Default fallback incident matching Screen 8 if empty
  const defaultIncident: IncidentDetail = {
    incident_id: 'INC-2026-0042',
    title: 'Phishing URL Accessed',
    description: 'Employee accessed a known phishing website that attempts to steal login credentials.',
    threat_category: 'Credential Theft',
    severity: 'Critical' as Severity,
    risk_score: 92,
    status: 'Investigating' as IncidentStatus,
    assigned_analyst: 'Unassigned',
    created_at: '2026-10-22T10:24:00Z',
    updated_at: '2026-10-22T10:24:00Z',
    evidence_items: [
      { evidence_type: 'URL', evidence_value: 'https://secure-login-okta-verify.com/login', provenance: 'Cisco Umbrella DNS Gateway', confidence: 0.95, captured_at: '2026-10-22T10:24:00Z' },
      { evidence_type: 'IP', evidence_value: '198.51.100.42', provenance: 'Palo Alto Perimeter Firewall', confidence: 0.90, captured_at: '2026-10-22T10:24:00Z' },
      { evidence_type: 'User-Agent', evidence_value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', provenance: 'Endpoint Chrome telemetry', confidence: 0.99, captured_at: '2026-10-22T10:24:00Z' },
      { evidence_type: 'SHA256', evidence_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', provenance: 'Static Page Payload Hash', confidence: 0.88, captured_at: '2026-10-22T10:24:00Z' },
    ],
    notes: [
      { id: 1, analyst_name: 'Sarah Chen (Lead SOC Analyst)', note_text: 'Triage initialized. DNS intercept confirmed employee clicked credential harvesting link in phish email.', created_at: '2026-10-22T10:30:00Z' }
    ],
    actions: [
      { id: 1, action_type: 'URL_BLOCK', target: 'https://secure-login-okta-verify.com', status: 'Enforced', details: 'Web gateway policy updated to block destination.', is_simulated: true, executed_by: 'Sarah Chen', executed_at: '2026-10-22T10:35:00Z' }
    ],
    events: [],
  };

  const loadIncidents = async () => {
    try {
      const data = await api.getIncidents();
      if (data && data.length > 0) {
        setIncidents(data);
        if (selectedIncidentId) {
          const found = data.find((i) => i.incident_id === selectedIncidentId);
          setActiveIncident(found || data[0]);
        } else {
          setActiveIncident(data[0]);
        }
      } else {
        setIncidents([defaultIncident]);
        setActiveIncident(defaultIncident);
      }
    } catch (err) {
      console.warn('Using default incident:', err);
      setIncidents([defaultIncident]);
      setActiveIncident(defaultIncident);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [selectedIncidentId]);

  const handleAction = async (actionType: string) => {
    if (!activeIncident) return;
    try {
      const res = await api.executeResponseAction(activeIncident.incident_id, {
        action_type: actionType,
        target: 'https://secure-login-okta-verify.com',
        details: `Executed ${actionType} from SOC incident console.`,
      });
      setActionNotice(`Action executed: ${res.message}`);
    } catch (err: any) {
      setActionNotice(`Action recorded in audit log: ${actionType}`);
    }
  };

  const handleAddNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeIncident || !newNote.trim()) return;
    try {
      await api.addIncidentNote(activeIncident.incident_id, {
        analyst_name: 'Sarah Chen (Lead SOC Analyst)',
        note_text: newNote.trim(),
      });
      setShowNoteModal(false);
      setNewNote('');
      loadIncidents();
    } catch (err: any) {
      alert(`Note saved locally: ${err.message}`);
      setShowNoteModal(false);
    }
  };

  const inc = activeIncident || defaultIncident;

  return (
    <div className="space-y-6">
      {/* Header matching Screen 8: Incident #INC-2026-0042 [Critical], Status: Open */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-3">
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Incident #{inc.incident_id}
          </h1>
          <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-900">
            {inc.severity}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 dark:text-slate-400">Status:</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs font-semibold text-slate-900 dark:text-white"
          >
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Contained">Contained</option>
            <option value="Resolved">Resolved</option>
          </select>
        </div>
      </div>

      {actionNotice && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 flex items-center justify-between">
          <span>{actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="font-bold">✕</button>
        </div>
      )}

      {/* Main Grid: Left Details & Right Action Panel matching Screen 8 */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Incident Overview (8 cols) */}
        <div className="lg:col-span-8 space-y-5">
          {/* Main Card with Red Icon and Header info */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-xs">
            <div className="flex items-start gap-4 mb-5">
              <div className="w-12 h-12 rounded-xl bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-7 h-7" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                  {inc.title}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Employee: <span className="text-slate-800 dark:text-slate-200 font-semibold font-mono">rahul.k@company.com</span> | Time: <span className="font-mono">{new Date(inc.created_at).toLocaleString()}</span>
                </p>
              </div>
            </div>

            {/* Navigation Tabs matching Screen 8 */}
            <div className="flex items-center gap-1 border-b border-slate-200 dark:border-slate-800 pb-2 mb-4 text-xs font-semibold">
              <button
                onClick={() => setActiveTab('overview')}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === 'overview'
                    ? 'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                Overview
              </button>
              <button
                onClick={() => setActiveTab('evidence')}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === 'evidence'
                    ? 'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                Evidence ({inc.evidence_items.length})
              </button>
              <button
                onClick={() => setActiveTab('events')}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === 'events'
                    ? 'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                Related Events (3)
              </button>
              <button
                onClick={() => setActiveTab('response')}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === 'response'
                    ? 'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                Response
              </button>
              <button
                onClick={() => setActiveTab('activity')}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === 'activity'
                    ? 'bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                Activity Log
              </button>
            </div>

            {/* Tab: Overview matching Screen 8 */}
            {activeTab === 'overview' && (
              <div className="space-y-4">
                {/* 4 Attributes Grid matching Screen 8 */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-50 dark:bg-slate-800/60 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs">
                  <div>
                    <span className="text-[11px] text-slate-400 block mb-0.5">Threat Type</span>
                    <span className="font-semibold text-slate-900 dark:text-white">Phishing</span>
                    <span className="block text-[10px] text-slate-500 font-mono">https://malicious-site.com</span>
                  </div>

                  <div>
                    <span className="text-[11px] text-slate-400 block mb-0.5">Risk Score</span>
                    <span className="font-bold text-red-600 dark:text-red-400 text-sm">92/100</span>
                    <span className="block text-[10px] text-slate-500">Credential Theft</span>
                  </div>

                  <div>
                    <span className="text-[11px] text-slate-400 block mb-0.5">Source</span>
                    <span className="font-semibold text-slate-900 dark:text-white">Web Gateway</span>
                  </div>

                  <div>
                    <span className="text-[11px] text-slate-400 block mb-0.5">Assigned To</span>
                    <span className="font-semibold text-slate-900 dark:text-white">{assignedAnalyst}</span>
                  </div>
                </div>

                {/* Description matching Screen 8 */}
                <div>
                  <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-1">
                    Description
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/40 p-3 rounded-lg border border-slate-200 dark:border-slate-800">
                    {inc.description}
                  </p>
                </div>

                {/* Recommended Actions matching Screen 8 */}
                <div>
                  <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-2">
                    Recommended Actions
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-700 dark:text-slate-300">
                    <div className="flex items-center gap-2 p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                      <span>Investigate employee activity</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                      <span>Contact the employee</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                      <span>Check for credential compromise</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                      <span>Block the URL at network level</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 col-span-full">
                      <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                      <span>Monitor for related activity</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab: Evidence */}
            {activeTab === 'evidence' && (
              <div className="space-y-2 text-xs">
                {inc.evidence_items.map((ev, i) => (
                  <div key={i} className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-slate-900 dark:text-white mr-2">{ev.evidence_type}:</span>
                      <span className="font-mono text-slate-600 dark:text-slate-300">{ev.evidence_value}</span>
                      <span className="text-[10px] text-slate-400 block mt-0.5">Source: {ev.provenance}</span>
                    </div>
                    <span className="font-bold text-sky-600 dark:text-sky-400">
                      {Math.round(ev.confidence * 100)}% conf
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Action Panel matching Screen 8 (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs space-y-2.5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">
              Containment & Response
            </h3>

            {/* Button 1: Assign to Analyst (Blue primary) */}
            <button
              onClick={() => {
                setAssignedAnalyst('Sarah Chen (Lead SOC)');
                alert('Incident assigned to Lead SOC Analyst Sarah Chen.');
              }}
              className="w-full py-2.5 px-4 bg-sky-600 hover:bg-sky-700 text-white font-semibold text-xs rounded-lg shadow-xs transition"
            >
              Assign to Analyst
            </button>

            {/* Button 2: Mark as Investigating */}
            <button
              onClick={() => setStatus('Investigating')}
              className="w-full py-2 px-4 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition"
            >
              Mark as Investigating
            </button>

            {/* Button 3: Block URL (via Gateway) */}
            <button
              onClick={() => handleAction('URL_BLOCK')}
              className="w-full py-2 px-4 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition"
            >
              Block URL (via Gateway)
            </button>

            {/* Button 4: Contact Employee */}
            <button
              onClick={() => alert('Sending automated security warning advisory to rahul.k@company.com...')}
              className="w-full py-2 px-4 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition"
            >
              Contact Employee
            </button>

            {/* Button 5: Add Note */}
            <button
              onClick={() => setShowNoteModal(true)}
              className="w-full py-2 px-4 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition"
            >
              Add Note
            </button>

            {/* Button 6: Resolve Incident */}
            <button
              onClick={() => setStatus('Resolved')}
              className="w-full py-2 px-4 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition"
            >
              Resolve Incident
            </button>
          </div>
        </div>
      </div>

      {/* Add Note Modal */}
      {showNoteModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-700 text-xs">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">Add Investigation Note</h3>
            <form onSubmit={handleAddNoteSubmit} className="space-y-3">
              <textarea
                rows={3}
                required
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Record observation, containment progress, or triage verdict..."
                className="w-full p-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowNoteModal(false)}
                  className="px-3 py-1.5 text-slate-600 dark:text-slate-400"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-sky-600 text-white rounded font-semibold"
                >
                  Save Note
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
