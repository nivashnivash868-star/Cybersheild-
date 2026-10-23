import React, { useState } from 'react';
import {
  BarChart3, Download, FileText, Calendar, Filter, Sparkles,
  TrendingUp, ShieldCheck, CheckCircle2, AlertTriangle
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend
} from 'recharts';
import { useTheme } from '../context/ThemeContext';

export const ReportsPage: React.FC = () => {
  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState<'trends' | 'threats' | 'employees' | 'leaks' | 'custom'>('trends');
  const [timeRange, setTimeRange] = useState('Last 30 Days');
  const [generating, setGenerating] = useState(false);

  // Sample data matching Screen 11
  const reportsData = [
    { period: 'Sep 22', phishing: 300, malware: 200, dataLeak: 150, suspiciousUrl: 80 },
    { period: 'Sep 29', phishing: 420, malware: 260, dataLeak: 210, suspiciousUrl: 130 },
    { period: 'Oct 06', phishing: 360, malware: 310, dataLeak: 180, suspiciousUrl: 100 },
    { period: 'Oct 13', phishing: 510, malware: 390, dataLeak: 290, suspiciousUrl: 190 },
    { period: 'Oct 20', phishing: 480, malware: 340, dataLeak: 240, suspiciousUrl: 160 },
  ];

  const handleGenerateReport = () => {
    setGenerating(true);
    setTimeout(() => {
      setGenerating(false);
      alert('Security Report compiled and ready for download: CYBERSHIELD_EXECUTIVE_AUDIT_Q4.pdf');
    }, 1200);
  };

  return (
    <div className="space-y-6">
      {/* Header matching Screen 11 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Security Reports
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Enterprise analytics, threat trends, and compliance reporting
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300"
          >
            <option value="Last 30 Days">Last 30 Days</option>
            <option value="Last 90 Days">Last 90 Days</option>
            <option value="Year to Date">Year to Date</option>
          </select>

          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{generating ? 'Compiling...' : 'Generate Report'}</span>
          </button>
        </div>
      </div>

      {/* Navigation Sub-Tabs matching Screen 11 */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('trends')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'trends'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Threat Trends
        </button>
        <button
          onClick={() => setActiveTab('threats')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'threats'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Top Threats
        </button>
        <button
          onClick={() => setActiveTab('employees')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'employees'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Employee Risk
        </button>
        <button
          onClick={() => setActiveTab('leaks')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'leaks'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Data Leaks
        </button>
        <button
          onClick={() => setActiveTab('custom')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'custom'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Custom Reports
        </button>
      </div>

      {/* Main Bar Chart matching Screen 11 */}
      <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Threat Trends Timeline</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Weekly threat volume categorized by attack vector</p>
          </div>
        </div>

        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={reportsData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                vertical={false}
                stroke={theme === 'dark' ? '#334155' : '#f1f5f9'}
              />
              <XAxis
                dataKey="period"
                tickLine={false}
                axisLine={{ stroke: theme === 'dark' ? '#475569' : '#cbd5e1' }}
                tick={{ fill: theme === 'dark' ? '#94a3b8' : '#64748b', fontSize: 11 }}
              />
              <YAxis
                tickLine={false}
                axisLine={false}
                tick={{ fill: theme === 'dark' ? '#94a3b8' : '#64748b', fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
                  borderColor: theme === 'dark' ? '#334155' : '#e2e8f0',
                  color: theme === 'dark' ? '#f8fafc' : '#0f172a',
                  borderRadius: '8px',
                  fontSize: '11px',
                }}
              />
              <Legend
                verticalAlign="bottom"
                wrapperStyle={{ paddingTop: '16px', fontSize: '11px' }}
              />
              <Bar dataKey="phishing" name="Phishing" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              <Bar dataKey="malware" name="Malware" fill="#0284c7" radius={[4, 4, 0, 0]} />
              <Bar dataKey="dataLeak" name="Data Leak" fill="#f97316" radius={[4, 4, 0, 0]} />
              <Bar dataKey="suspiciousUrl" name="Suspicious URL" fill="#10b981" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">Total Threats Analyzed</span>
          <div className="text-2xl font-bold text-slate-900 dark:text-white mt-1">4,812</div>
          <p className="text-[10px] text-emerald-600 mt-0.5">+12% vs previous period</p>
        </div>

        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">Mean Time to Detect (MTTD)</span>
          <div className="text-2xl font-bold text-sky-600 dark:text-sky-400 mt-1">1.4 min</div>
          <p className="text-[10px] text-emerald-600 mt-0.5">Automated ML classification</p>
        </div>

        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">Mean Time to Remediate (MTTR)</span>
          <div className="text-2xl font-bold text-emerald-600 dark:text-emerald-400 mt-1">8.2 min</div>
          <p className="text-[10px] text-slate-400 mt-0.5">Automated web gateway block</p>
        </div>

        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">SOC 2 Compliance Score</span>
          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400 mt-1">98.4%</div>
          <p className="text-[10px] text-emerald-600 mt-0.5">Audit log integrity verified</p>
        </div>
      </div>
    </div>
  );
};
