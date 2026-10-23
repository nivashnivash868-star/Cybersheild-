import React, { useState } from 'react';
import {
  Activity, Globe, Mail, FileText, Download, Filter, Search,
  CheckCircle2, AlertTriangle, ShieldAlert, ArrowUpRight, Radio
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { MonitoringSourcesPage } from './MonitoringSourcesPage';

interface Props {
  initialSubTab?: 'web' | 'email' | 'files' | 'sources';
}

export const MonitoringCenterPage: React.FC<Props> = ({ initialSubTab = 'web' }) => {
  const { theme } = useTheme();
  const [subTab, setSubTab] = useState<'web' | 'email' | 'files' | 'sources'>(initialSubTab);
  const [timeRange, setTimeRange] = useState('Last 24 Hours');
  const [riskFilter, setRiskFilter] = useState('All Risk Levels');
  const [categoryFilter, setCategoryFilter] = useState('All Categories');
  const [search, setSearch] = useState('');

  // Sample data matching Screen 4
  const webActivityRecords = [
    {
      id: 'WEB-001',
      time: '10:24 AM',
      employee: 'rahul.k@company.com',
      url: 'https://malicious-site.com',
      category: 'Malware',
      risk: 'High',
      action: 'Blocked',
    },
    {
      id: 'WEB-002',
      time: '10:10 AM',
      employee: 'priya.s@company.com',
      url: 'https://drive.google.com',
      category: 'File Upload',
      risk: 'Medium',
      action: 'Allowed',
    },
    {
      id: 'WEB-003',
      time: '09:55 AM',
      employee: 'arun.m@company.com',
      url: 'https://unknown-site.xyz',
      category: 'Phishing',
      risk: 'Critical',
      action: 'Blocked',
    },
    {
      id: 'WEB-004',
      time: '09:40 AM',
      employee: 'divya.r@company.com',
      url: 'https://github.com',
      category: 'Development',
      risk: 'Low',
      action: 'Allowed',
    },
    {
      id: 'WEB-005',
      time: '09:25 AM',
      employee: 'karan.v@company.com',
      url: 'https://suspicious-link.net',
      category: 'Suspicious',
      risk: 'High',
      action: 'Under Review',
    },
    {
      id: 'WEB-006',
      time: '08:50 AM',
      employee: 'sneha.t@company.com',
      url: 'https://login-microsoft-auth.com',
      category: 'Credential Harvest',
      risk: 'Critical',
      action: 'Blocked',
    },
  ];

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'Critical':
        return 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/60';
      case 'High':
        return 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/60';
      case 'Medium':
        return 'bg-yellow-50 dark:bg-yellow-950/60 text-yellow-600 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900/60';
      default:
        return 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/60';
    }
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'Blocked':
        return 'text-red-600 dark:text-red-400 font-semibold';
      case 'Allowed':
        return 'text-emerald-600 dark:text-emerald-400 font-semibold';
      case 'Under Review':
        return 'text-amber-600 dark:text-amber-400 font-semibold';
      default:
        return 'text-slate-600 dark:text-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation matching Screen 4 */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          onClick={() => setSubTab('web')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'web'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Web Activity
        </button>
        <button
          onClick={() => setSubTab('email')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'email'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Email Security
        </button>
        <button
          onClick={() => setSubTab('files')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'files'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          File & Data Monitoring
        </button>
        <button
          onClick={() => setSubTab('sources')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'sources'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          24/7 Telemetry Feeds
        </button>
      </div>

      {subTab === 'sources' ? (
        <MonitoringSourcesPage />
      ) : (
        <>
          {/* Header matching Screen 4 */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                Web Activity Monitoring
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Real-time monitoring of website access and URL analysis
              </p>
            </div>

            <button
              onClick={() => alert('Exporting Web Activity audit report in CSV format...')}
              className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition self-start sm:self-auto"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          </div>

          {/* Filters Bar matching Screen 4 */}
          <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center flex-wrap gap-2 text-xs">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
              >
                <option value="Last 24 Hours">Last 24 Hours</option>
                <option value="Last 7 Days">Last 7 Days</option>
                <option value="Last 30 Days">Last 30 Days</option>
              </select>

              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
              >
                <option value="All Risk Levels">All Risk Levels</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
              >
                <option value="All Categories">All Categories</option>
                <option value="Malware">Malware</option>
                <option value="Phishing">Phishing</option>
                <option value="File Upload">File Upload</option>
                <option value="Suspicious">Suspicious</option>
              </select>
            </div>

            <div className="relative flex-1 max-w-xs">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search URL or employee..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>
          </div>

          {/* Web Activity Table matching Screen 4 */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">Employee</th>
                    <th className="py-3 px-4">URL</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Risk</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {webActivityRecords.map((rec) => (
                    <tr key={rec.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">{rec.time}</td>
                      <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{rec.employee}</td>
                      <td className="py-3 px-4 font-mono text-[11px] text-sky-600 dark:text-sky-400 truncate max-w-xs">
                        {rec.url}
                      </td>
                      <td className="py-3 px-4 text-slate-700 dark:text-slate-300">{rec.category}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadge(rec.risk)}`}>
                          {rec.risk}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={getActionBadge(rec.action)}>{rec.action}</span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => alert(`Inspecting Web Activity Record ${rec.id}: ${rec.url}`)}
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
        </>
      )}
    </div>
  );
};
