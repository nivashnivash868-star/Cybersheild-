import React, { useState } from 'react';
import {
  Bell, Mail, Phone, Search, Filter, CheckCircle2,
  Clock, AlertTriangle, RefreshCw
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export const NotificationsPage: React.FC = () => {
  const { theme } = useTheme();
  const [channelTab, setChannelTab] = useState<'All' | 'Email' | 'SMS'>('All');
  const [search, setSearch] = useState('');

  // Sample data matching Screen 12
  const notifications = [
    {
      id: 'NOTIF-01',
      type: 'Security Alert',
      time: '10:24 AM',
      message: 'Suspicious website blocked for rahul.k@company.com',
      channel: 'Email',
      status: 'Delivered',
    },
    {
      id: 'NOTIF-02',
      time: '09:50 AM',
      message: 'Critical secret leak detected in git repository',
      channel: 'SMS',
      status: 'Sent',
    },
    {
      id: 'NOTIF-03',
      time: '09:12 AM',
      message: 'Phishing email quarantined by Exchange rule',
      channel: 'Email',
      status: 'Delivered',
    },
    {
      id: 'NOTIF-04',
      time: '08:45 AM',
      message: 'Incident #INC-0042 assigned to Tier-1 Analyst',
      channel: 'System',
      status: 'Read',
    },
    {
      id: 'NOTIF-05',
      type: 'Health Digest',
      time: '08:00 AM',
      message: 'Daily SOC telemetry health digest delivered',
      channel: 'Email',
      status: 'Delivered',
    },
  ];

  const filtered = notifications.filter((n) => {
    const matchesChannel = channelTab === 'All' || n.channel === channelTab;
    const matchesSearch =
      !search ||
      n.message.toLowerCase().includes(search.toLowerCase()) ||
      (n.type ? n.type.toLowerCase().includes(search.toLowerCase()) : false);
    return matchesChannel && matchesSearch;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Delivered':
        return 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 font-semibold';
      case 'Sent':
        return 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-400 border border-sky-200 dark:border-sky-800';
      case 'Read':
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700';
      default:
        return 'bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header matching Screen 12 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Notifications
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Automated alerts dispatched to SOC analysts and personnel
          </p>
        </div>

        <div className="relative flex-1 max-w-xs self-start sm:self-auto">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search notifications..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
        </div>
      </div>

      {/* Tabs matching Screen 12 */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-semibold">
        <button
          onClick={() => setChannelTab('All')}
          className={`px-3 py-1.5 rounded-lg transition ${
            channelTab === 'All'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          All
        </button>
        <button
          onClick={() => setChannelTab('Email')}
          className={`px-3 py-1.5 rounded-lg transition ${
            channelTab === 'Email'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Email
        </button>
        <button
          onClick={() => setChannelTab('SMS')}
          className={`px-3 py-1.5 rounded-lg transition ${
            channelTab === 'SMS'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          SMS
        </button>
      </div>

      {/* Table matching Screen 12 */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Message</th>
                <th className="py-3 px-4">Channel</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filtered.map((n) => (
                <tr key={n.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{n.type}</td>
                  <td className="py-3 px-4 font-mono text-slate-500 dark:text-slate-400">{n.time}</td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 max-w-md">{n.message}</td>
                  <td className="py-3 px-4">
                    <span className="font-medium text-slate-600 dark:text-slate-400">{n.channel}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] ${getStatusBadge(n.status)}`}>
                      {n.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => alert(`Notification ${n.id}: ${n.message}`)}
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
