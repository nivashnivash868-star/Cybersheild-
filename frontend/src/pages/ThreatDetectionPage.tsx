import React, { useState } from 'react';
import {
  Mail, Globe, FileSearch, Network, Download, Search,
  AlertTriangle, CheckCircle2, ShieldAlert, Sparkles, Filter
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { PhishingPage } from './PhishingPage';
import { FileAnalysisPage } from './FileAnalysisPage';
import { NetworkAnomalyPage } from './NetworkAnomalyPage';

interface Props {
  initialSubTab?: 'phishing' | 'url' | 'files' | 'network';
}

export const ThreatDetectionPage: React.FC<Props> = ({ initialSubTab = 'phishing' }) => {
  const { theme } = useTheme();
  const [subTab, setSubTab] = useState<'phishing' | 'url' | 'files' | 'network'>(initialSubTab);
  const [timeRange, setTimeRange] = useState('Last 7 Days');
  const [riskFilter, setRiskFilter] = useState('All Risk Levels');
  const [search, setSearch] = useState('');

  // Sample data matching Screen 5
  const phishingRecords = [
    {
      id: 'PHISH-001',
      time: '10:12 AM',
      employee: 'priya.s@company.com',
      subject: 'Urgent: Verify Account',
      risk: 'Critical',
      result: 'Phishing',
    },
    {
      id: 'PHISH-002',
      time: '09:50 AM',
      employee: 'rahul.k@company.com',
      subject: 'Invoice Attached',
      risk: 'High',
      result: 'Suspicious',
    },
    {
      id: 'PHISH-003',
      time: '09:20 AM',
      employee: 'arun.m@company.com',
      subject: 'Meeting Schedule',
      risk: 'Medium',
      result: 'Clean',
    },
    {
      id: 'PHISH-004',
      time: '08:10 AM',
      employee: 'divya.r@company.com',
      subject: 'Password Reset',
      risk: 'Low',
      result: 'Clean',
    },
    {
      id: 'PHISH-005',
      time: '07:45 AM',
      employee: 'karan.v@company.com',
      subject: 'Confidential Document',
      risk: 'High',
      result: 'Phishing',
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

  const getResultBadge = (result: string) => {
    switch (result) {
      case 'Phishing':
        return 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 font-bold';
      case 'Suspicious':
        return 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 font-semibold';
      case 'Clean':
        return 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-semibold';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation tabs matching Screen 5 */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          onClick={() => setSubTab('phishing')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'phishing'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Phishing Email
        </button>
        <button
          onClick={() => setSubTab('url')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'url'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          URL Scanner
        </button>
        <button
          onClick={() => setSubTab('files')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'files'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          File Analysis
        </button>
        <button
          onClick={() => setSubTab('network')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
            subTab === 'network'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Network Anomalies
        </button>
      </div>

      {subTab === 'url' ? (
        <PhishingPage initialSubmissionType="url" />
      ) : subTab === 'files' ? (
        <FileAnalysisPage />
      ) : subTab === 'network' ? (
        <NetworkAnomalyPage />
      ) : (
        <>
          {/* Header matching Screen 5 */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                Phishing Email Analysis
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                AI-powered detection of phishing emails
              </p>
            </div>

            <button
              onClick={() => alert('Exporting Phishing Analysis report...')}
              className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition self-start sm:self-auto"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          </div>

          {/* Filters matching Screen 5 */}
          <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300"
              >
                <option value="Last 7 Days">Last 7 Days</option>
                <option value="Last 24 Hours">Last 24 Hours</option>
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
            </div>

            <div className="relative flex-1 max-w-xs">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search emails, subjects..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>
          </div>

          {/* Table matching Screen 5 */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">Employee</th>
                    <th className="py-3 px-4">Subject</th>
                    <th className="py-3 px-4">Risk</th>
                    <th className="py-3 px-4">Result</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {phishingRecords.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">{item.time}</td>
                      <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{item.employee}</td>
                      <td className="py-3 px-4 text-slate-700 dark:text-slate-300 font-medium">{item.subject}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadge(item.risk)}`}>
                          {item.risk}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] ${getResultBadge(item.result)}`}>
                          {item.result}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSubTab('url')}
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
