import React, { useState, useEffect } from 'react';
import {
  Users, ShieldAlert, AlertTriangle, Flame, Globe, KeyRound,
  ArrowUp, ArrowDown, Activity, ChevronDown, Eye, CheckCircle2,
  ExternalLink, Clock
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { DashboardMetrics, SecurityEvent, Severity } from '../types';

interface Props {
  onNavigateToTab: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
}

export const DashboardPage: React.FC<Props> = ({ onNavigateToTab, onSelectIncident }) => {
  const { theme } = useTheme();
  const [timeRange, setTimeRange] = useState('Last 24 Hours');
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);

  // Multi-line activity data matching Screen 2
  const activityData = [
    { time: '00:00', phishing: 12, malware: 8, dataLeak: 5, suspiciousUrl: 10 },
    { time: '04:00', phishing: 18, malware: 14, dataLeak: 8, suspiciousUrl: 16 },
    { time: '08:00', phishing: 45, malware: 28, dataLeak: 22, suspiciousUrl: 34 },
    { time: '12:00', phishing: 68, malware: 35, dataLeak: 30, suspiciousUrl: 42 },
    { time: '16:00', phishing: 52, malware: 32, dataLeak: 25, suspiciousUrl: 38 },
    { time: '20:00', phishing: 38, malware: 20, dataLeak: 16, suspiciousUrl: 26 },
    { time: '24:00', phishing: 25, malware: 15, dataLeak: 12, suspiciousUrl: 18 },
  ];

  // Threat Category Distribution matching Screen 2
  const donutData = [
    { name: 'Phishing', value: 35, color: '#8b5cf6' },
    { name: 'Malware', value: 20, color: '#0284c7' },
    { name: 'Data Leak', value: 18, color: '#f97316' },
    { name: 'Suspicious URLs', value: 15, color: '#10b981' },
    { name: 'Unauthorized Access', value: 7, color: '#f43f5e' },
    { name: 'Others', value: 5, color: '#64748b' },
  ];

  // Recent Security Alerts matching Screen 2
  const recentAlerts = [
    {
      id: 'ALT-101',
      time: '10:24 AM',
      employee: 'rahul.k@company.com',
      type: 'Phishing URL',
      details: 'Accessed malicious site',
      risk: 'High' as Severity,
      status: 'Open',
      incidentId: 'INC-2026-0042',
    },
    {
      id: 'ALT-102',
      time: '09:50 AM',
      employee: 'priya.s@company.com',
      type: 'Data Leak',
      details: 'Tried to upload sensitive file',
      risk: 'Critical' as Severity,
      status: 'Open',
      incidentId: 'INC-2026-0041',
    },
    {
      id: 'ALT-103',
      time: '09:12 AM',
      employee: 'arun.m@company.com',
      type: 'Suspicious Email',
      details: 'Received phishing email',
      risk: 'High' as Severity,
      status: 'Investigating',
      incidentId: 'INC-2026-0039',
    },
    {
      id: 'ALT-104',
      time: '08:45 AM',
      employee: 'divya.r@company.com',
      type: 'Malware',
      details: 'Downloaded malicious file',
      risk: 'Medium' as Severity,
      status: 'Resolved',
      incidentId: 'INC-2026-0038',
    },
    {
      id: 'ALT-105',
      time: '07:30 AM',
      employee: 'karan.v@company.com',
      type: 'Brute Force',
      details: 'Multiple failed SSH attempts',
      risk: 'Critical' as Severity,
      status: 'Investigating',
      incidentId: 'INC-2026-0040',
    },
  ];

  const getRiskBadge = (risk: Severity) => {
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

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Open':
        return 'bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/50';
      case 'Investigating':
        return 'bg-sky-50 dark:bg-sky-950/50 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-900/50';
      case 'Resolved':
        return 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner matching Screen 2 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Welcome to CYBERSHIELD AI
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time monitoring, threat detection and incident response
          </p>
        </div>

        {/* System Active Indicator */}
        <div className="flex items-center gap-2 bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 px-3 py-1.5 rounded-full text-xs self-start sm:self-auto font-medium">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="font-semibold text-slate-900 dark:text-white text-[11px]">System Active</span>
          <span className="text-[10px] opacity-75">24/7 Monitoring</span>
        </div>
      </div>

      {/* 2. 6 KPI Cards matching Screen 2 */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3.5">
        {/* Card 1: Employees */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Employees</span>
            <div className="w-6 h-6 rounded bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400 flex items-center justify-center">
              <Users className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">128</div>
          <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <span>+2.1% this week</span>
          </div>
        </div>

        {/* Card 2: Security Events */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Security Events</span>
            <div className="w-6 h-6 rounded bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-400 flex items-center justify-center">
              <Activity className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">4,812</div>
          <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <ArrowUp className="w-3 h-3" />
            <span>12%</span>
          </div>
        </div>

        {/* Card 3: Active Incidents */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Active Incidents</span>
            <div className="w-6 h-6 rounded bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400 flex items-center justify-center">
              <AlertTriangle className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">24</div>
          <div className="text-[10px] text-red-600 dark:text-red-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <ArrowUp className="w-3 h-3" />
            <span>4</span>
          </div>
        </div>

        {/* Card 4: Critical Threats */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Critical Threats</span>
            <div className="w-6 h-6 rounded bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400 flex items-center justify-center">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-red-600 dark:text-red-400">7</div>
          <div className="text-[10px] text-red-600 dark:text-red-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <ArrowUp className="w-3 h-3" />
            <span>2</span>
          </div>
        </div>

        {/* Card 5: Suspicious URLs */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Suspicious URLs</span>
            <div className="w-6 h-6 rounded bg-amber-50 dark:bg-amber-950 text-amber-600 dark:text-amber-400 flex items-center justify-center">
              <Globe className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">26</div>
          <div className="text-[10px] text-red-600 dark:text-red-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <ArrowUp className="w-3 h-3" />
            <span>5</span>
          </div>
        </div>

        {/* Card 6: Data Leak Alerts */}
        <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span className="font-medium text-[11px]">Data Leak Alerts</span>
            <div className="w-6 h-6 rounded bg-purple-50 dark:bg-purple-950 text-purple-600 dark:text-purple-400 flex items-center justify-center">
              <KeyRound className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">15</div>
          <div className="text-[10px] text-red-600 dark:text-red-400 font-semibold flex items-center gap-0.5 mt-0.5">
            <span>+4</span>
          </div>
        </div>
      </div>

      {/* 3. Charts Row matching Screen 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Chart: Security Events Last 24 Hours (7 cols) */}
        <div className="lg:col-span-7 bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800/80 mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Security Events (Last 24 Hours)
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Hourly telemetry trends across detection engines
              </p>
            </div>

            <div className="flex items-center gap-1.5 text-xs">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="px-2.5 py-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none"
              >
                <option value="Last 24 Hours">Last 24 Hours</option>
                <option value="Last 7 Days">Last 7 Days</option>
                <option value="Last 30 Days">Last 30 Days</option>
              </select>
            </div>
          </div>

          {/* Area Chart */}
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPhishing" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorMalware" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0284c7" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#0284c7" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorDataLeak" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorSuspiciousUrl" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  vertical={false}
                  stroke={theme === 'dark' ? '#334155' : '#f1f5f9'}
                />
                <XAxis
                  dataKey="time"
                  tickLine={false}
                  axisLine={{ stroke: theme === 'dark' ? '#475569' : '#cbd5e1' }}
                  tick={{ fill: theme === 'dark' ? '#94a3b8' : '#64748b', fontSize: 10 }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: theme === 'dark' ? '#94a3b8' : '#64748b', fontSize: 10 }}
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
                <Area type="monotone" dataKey="phishing" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorPhishing)" strokeWidth={2} />
                <Area type="monotone" dataKey="malware" stroke="#0284c7" fillOpacity={1} fill="url(#colorMalware)" strokeWidth={2} />
                <Area type="monotone" dataKey="dataLeak" stroke="#f97316" fillOpacity={1} fill="url(#colorDataLeak)" strokeWidth={2} />
                <Area type="monotone" dataKey="suspiciousUrl" stroke="#10b981" fillOpacity={1} fill="url(#colorSuspiciousUrl)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Legend matching Screen 2 */}
          <div className="flex items-center justify-center flex-wrap gap-4 pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-600 dark:text-slate-400">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              <span>Phishing</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-500" />
              <span>Malware</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              <span>Data Leak</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span>Suspicious URL</span>
            </div>
          </div>
        </div>

        {/* Right Chart: Threat Category Distribution Donut (5 cols) */}
        <div className="lg:col-span-5 bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
          <div className="pb-3 border-b border-slate-100 dark:border-slate-800/80 mb-2">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Threat Category Distribution
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Proportionate classification across all active events
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-2">
            {/* Donut Chart with Center Total */}
            <div className="w-48 h-48 relative flex items-center justify-center shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {donutData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.color}
                        stroke={theme === 'dark' ? '#0f172a' : '#ffffff'}
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(val: any, name: any) => [`${val}%`, name]}
                    contentStyle={{
                      backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
                      borderColor: theme === 'dark' ? '#334155' : '#e2e8f0',
                      color: theme === 'dark' ? '#f8fafc' : '#0f172a',
                      borderRadius: '8px',
                      fontSize: '11px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>

              <div className="absolute text-center pointer-events-none">
                <div className="text-lg font-bold text-slate-900 dark:text-white">4,812</div>
                <div className="text-[10px] font-medium text-slate-500 dark:text-slate-400">Events</div>
              </div>
            </div>

            {/* Legend on right with exact percentages */}
            <div className="space-y-2 text-xs flex-1 w-full sm:w-auto">
              {donutData.map((item) => (
                <div key={item.name} className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="text-slate-700 dark:text-slate-300">{item.name}</span>
                  </div>
                  <span className="font-bold text-slate-900 dark:text-white">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-2 text-[10px] text-slate-400 text-center border-t border-slate-100 dark:border-slate-800">
            Updated live via continuous telemetry ingestion
          </div>
        </div>
      </div>

      {/* 4. Bottom Table: Recent Security Alerts matching Screen 2 */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Recent Security Alerts
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              High-priority events requiring SOC analyst evaluation
            </p>
          </div>

          <button
            onClick={() => onNavigateToTab('incidents')}
            className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1"
          >
            <span>View All</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4">Time</th>
                <th className="py-2.5 px-4">Employee</th>
                <th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">Details</th>
                <th className="py-2.5 px-4">Risk</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {recentAlerts.map((alt) => (
                <tr key={alt.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">{alt.time}</td>
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{alt.employee}</td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 font-medium">{alt.type}</td>
                  <td className="py-3 px-4 text-slate-500 dark:text-slate-400">{alt.details}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadge(alt.risk)}`}>
                      {alt.risk}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getStatusBadge(alt.status)}`}>
                      {alt.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => {
                        if (onSelectIncident) {
                          onSelectIncident(alt.incidentId);
                        } else {
                          onNavigateToTab('incident_detail');
                        }
                      }}
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
    </div>
  );
};
