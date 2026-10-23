import React, { useState, useEffect } from 'react';
import {
  KeyRound, ShieldAlert, Search, Filter, AlertTriangle, CheckCircle2,
  Lock, EyeOff, RefreshCw, Sparkles, FileCode, Download, ExternalLink
} from 'lucide-react';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { SecretFinding, Severity } from '../types';

export const DLPPage: React.FC = () => {
  const { theme } = useTheme();
  const [findings, setFindings] = useState<SecretFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeFilter, setTimeFilter] = useState('Last 30 Days');
  const [severityFilter, setSeverityFilter] = useState('All Severity');
  const [sourceFilter, setSourceFilter] = useState('All Sources');
  const [search, setSearch] = useState('');

  // Scanner Form state
  const [scanText, setScanText] = useState('');
  const [sourceType, setSourceType] = useState('GitHub');
  const [locationRef, setLocationRef] = useState('repo:backend-payments/config.json');
  const [employeeEmail, setEmployeeEmail] = useState('marcus.chen@enterprise-corp.com');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<{ secrets_found_count: number; findings: SecretFinding[] } | null>(null);

  // Mock records matching Screen 6 if empty
  const defaultMockFindings: SecretFinding[] = [
    {
      id: 1,
      finding_id: 'DLP-001',
      secret_type: 'API Key',
      masked_value: 'sk_live_********************************',
      secret_hash: 'hash-001',
      source_type: 'GitHub',
      location_reference: 'repo:payment-service/config.json',
      exposure_scope: 'Public Repository',
      risk_score: 95,
      severity: 'Critical',
      status: 'Active',
      detected_at: '2026-10-22T09:50:00Z',
    },
    {
      id: 2,
      finding_id: 'DLP-002',
      secret_type: 'Password',
      masked_value: 'password=****************',
      secret_hash: 'hash-002',
      source_type: 'Code Repository',
      location_reference: 'repo:infra/deploy.sh',
      exposure_scope: 'Internal GitLab',
      risk_score: 85,
      severity: 'High',
      status: 'Remediated',
      detected_at: '2026-10-22T08:30:00Z',
    },
    {
      id: 3,
      finding_id: 'DLP-003',
      secret_type: 'Database URL',
      masked_value: 'postgresql://admin:****************@prod-db',
      secret_hash: 'hash-003',
      source_type: 'Database Pool',
      location_reference: 'slack:#dev-channel/snippet.env',
      exposure_scope: 'Corporate Slack',
      risk_score: 88,
      severity: 'High',
      status: 'Active',
      detected_at: '2026-10-22T07:15:00Z',
    },
    {
      id: 4,
      finding_id: 'DLP-004',
      secret_type: 'Access Token',
      masked_value: 'ya29.********************************',
      secret_hash: 'hash-004',
      source_type: 'Web Paste Site',
      location_reference: 'pastebin.com/raw/d849fa',
      exposure_scope: 'Public Web',
      risk_score: 72,
      severity: 'Medium',
      status: 'Remediated',
      detected_at: '2026-10-22T06:30:00Z',
    },
    {
      id: 5,
      finding_id: 'DLP-005',
      secret_type: 'Private Key',
      masked_value: '-----BEGIN RSA PRIVATE KEY-----',
      secret_hash: 'hash-005',
      source_type: 'Cloud Storage',
      location_reference: 's3://prod-backups/id_rsa',
      exposure_scope: 'Misconfigured S3 Bucket',
      risk_score: 92,
      severity: 'High',
      status: 'Active',
      detected_at: '2026-10-22T05:10:00Z',
    },
  ];

  const loadFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getDLPFindings();
      if (data && data.length > 0) {
        setFindings(data);
      } else {
        setFindings(defaultMockFindings);
      }
    } catch (err) {
      console.warn('Using default DLP findings:', err);
      setFindings(defaultMockFindings);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanText.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const findingsList = await api.scanDLP({
        content: scanText,
        source_location: `${sourceType}: ${locationRef}`,
        employee_email: employeeEmail || undefined,
      });
      setScanResult({
        secrets_found_count: findingsList.length,
        findings: findingsList,
      });
      await loadFindings();
    } catch (err: any) {
      alert(`DLP scan failed: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'Critical':
        return 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/60 font-bold';
      case 'High':
        return 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/60 font-semibold';
      case 'Medium':
        return 'bg-yellow-50 dark:bg-yellow-950/60 text-yellow-600 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900/60';
      default:
        return 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-900/60';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Active':
      case 'Open':
        return 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/60 font-semibold';
      case 'Investigating':
        return 'bg-sky-50 dark:bg-sky-950/60 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-900/60';
      case 'Resolved':
      case 'Remediated':
        return 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/60';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header matching Screen 6 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Potential Secrets Detected
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Detection of exposed API keys, tokens and sensitive data
          </p>
        </div>

        <button
          onClick={() => alert('Exporting DLP Secret Audit Report in CSV/JSON format...')}
          className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export</span>
        </button>
      </div>

      {/* Filters matching Screen 6 */}
      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center flex-wrap gap-2 text-xs">
          <select
            value={timeFilter}
            onChange={(e) => setTimeFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
          >
            <option value="Last 30 Days">Last 30 Days</option>
            <option value="Last 7 Days">Last 7 Days</option>
            <option value="Last 24 Hours">Last 24 Hours</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
          >
            <option value="All Severity">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>

          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
          >
            <option value="All Sources">All Sources</option>
            <option value="GitHub">GitHub</option>
            <option value="Code Repository">Code Repository</option>
            <option value="Database Pool">Database Pool</option>
            <option value="Web Paste Site">Web Paste Site</option>
            <option value="Cloud Storage">Cloud Storage</option>
          </select>
        </div>

        <div className="relative flex-1 max-w-xs">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
        </div>
      </div>

      {/* Secrets Table matching Screen 6 */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Secret Type</th>
                <th className="py-3 px-4">Secret</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">
                    {new Date(f.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 px-4 font-medium text-slate-800 dark:text-slate-200">{f.source_type}</td>
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{f.secret_type}</td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-[11px] bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
                      {f.masked_value}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] ${getStatusBadge(f.status)}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => alert(`Reviewing Secret Finding ${f.finding_id}: ${f.secret_type} at ${f.location_reference}`)}
                      className="px-2.5 py-1 text-xs font-semibold text-sky-600 dark:text-sky-400 hover:text-sky-700 dark:hover:text-sky-300 hover:bg-sky-50 dark:hover:bg-sky-950/60 rounded transition"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ad-Hoc Scanner Accordion Card */}
      <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
        <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-sky-600" />
          <span>Real-Time Code & Content Secret Scanner</span>
        </h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
          Paste configuration files, git commits, or messages to test automated detection and UI masking.
        </p>

        <form onSubmit={handleScanSubmit} className="space-y-3">
          <textarea
            rows={3}
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
            placeholder="export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport STRIPE_SECRET=sk_test_51A2345..."
            className="w-full font-mono text-xs p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={scanning || !scanText.trim()}
              className="px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs disabled:opacity-50"
            >
              {scanning ? 'Scanning...' : 'Scan for Exposed Credentials'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
