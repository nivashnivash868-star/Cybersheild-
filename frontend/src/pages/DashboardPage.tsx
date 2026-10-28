import React, { useCallback, useEffect, useState } from 'react';
import { Users, ShieldAlert, AlertTriangle, Globe, KeyRound, Activity, ExternalLink, RefreshCw } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { ActivityDataPoint, CategoryCount, DashboardMetrics, SecurityEvent, Severity } from '../types';
import { SimulatedBadge, SimulatedBanner } from '../components/common/Simulated';
import { EventInvestigation } from '../components/investigation/EventInvestigation';

interface Props {
  onNavigateToTab: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
}

const PALETTE = ['#8b5cf6', '#0284c7', '#f97316', '#10b981', '#f43f5e', '#eab308', '#64748b'];
const REFRESH_MS = 30000;

const parseUtc = (iso: string) => new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');

const riskBadge = (risk: Severity) => {
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

const Kpi: React.FC<{ label: string; value: number | string; note?: string; noteTone?: 'up' | 'down' | 'flat'; icon: React.ReactNode; tint: string; danger?: boolean }> =
  ({ label, value, note, noteTone = 'flat', icon, tint, danger }) => (
    <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
        <span className="font-medium text-[11px]">{label}</span>
        <div className={`w-6 h-6 rounded flex items-center justify-center ${tint}`}>{icon}</div>
      </div>
      <div className={`text-2xl font-bold ${danger ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-white'}`}>{value}</div>
      {note && (
        <div className={`text-[10px] font-semibold mt-0.5 ${noteTone === 'up' ? 'text-red-600 dark:text-red-400' : noteTone === 'down' ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'}`}>
          {note}
        </div>
      )}
    </div>
  );

export const DashboardPage: React.FC<Props> = ({ onNavigateToTab, onSelectIncident }) => {
  const { theme } = useTheme();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [timeline, setTimeline] = useState<ActivityDataPoint[]>([]);
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [alerts, setAlerts] = useState<SecurityEvent[]>([]);
  const [critical, setCritical] = useState<SecurityEvent[]>([]);
  const [eventId, setEventId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const [m, t, c, e, crit] = await Promise.all([
        api.getDashboardMetrics(), api.getActivityTimeline(), api.getCategoryDistribution(), api.getRecentEvents({ limit: 40 }), api.getCriticalAlerts(8),
      ]);
      setCritical(crit);
      setMetrics(m);
      setTimeline(t.map((p) => ({ ...p, time_label: p.bucket_end ? parseUtc(p.bucket_end).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : p.time_label })));
      setCategories(c);
      const serious = e.filter((x) => x.severity === 'Critical' || x.severity === 'High');
      setAlerts((serious.length ? serious : e).slice(0, 8));
      setUpdatedAt(new Date());
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const delta = (() => {
    if (!metrics) return undefined;
    const { events_last_24h: now, events_prev_24h: prev } = metrics;
    if (prev === 0) return { text: `${now.toLocaleString()} in the last 24h`, tone: 'flat' as const };
    const pct = Math.round(((now - prev) / prev) * 100);
    return { text: `${pct >= 0 ? '+' : ''}${pct}% vs previous 24h`, tone: (pct > 0 ? 'up' : 'down') as 'up' | 'down' };
  })();

  const axis = theme === 'dark' ? '#94a3b8' : '#64748b';
  const tooltipStyle = {
    backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff', borderColor: theme === 'dark' ? '#334155' : '#e2e8f0',
    color: theme === 'dark' ? '#f8fafc' : '#0f172a', borderRadius: '8px', fontSize: '11px',
  };
  const totalCategorised = categories.reduce((n, c) => n + c.count, 0);
  const hasEvents = (metrics?.total_events_analyzed ?? 0) > 0;
  const liveSources = metrics?.zetaris_connected_sources ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Welcome to CYBERSHIELD AI</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Threat detection and incident response across your connected data sources</p>
        </div>
        <div className="flex items-center gap-3 self-start sm:self-auto">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border ${liveSources > 0
            ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800/60'
            : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
            <span className={`h-2 w-2 rounded-full ${liveSources > 0 ? 'bg-emerald-500' : 'bg-slate-400'}`} />
            <span className="text-[11px] font-semibold">
              {liveSources > 0 ? `${liveSources} live data source${liveSources > 1 ? 's' : ''} (Zetaris)` : 'No live data source connected'}
            </span>
          </div>
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
        </div>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">
          Couldn't load the dashboard: {error}
        </div>
      )}

      {metrics && <SimulatedBanner simulated={metrics.simulated_events_total ?? 0} total={metrics.total_events_analyzed} />}

      <section aria-label="Critical alerts" className="bg-white dark:bg-slate-900 rounded-xl border border-red-200 dark:border-red-900/60 overflow-hidden">
        <div className="px-4 py-3 border-b border-red-100 dark:border-red-900/40 bg-red-50/60 dark:bg-red-950/20 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-red-700 dark:text-red-300 flex items-center gap-2"><ShieldAlert className="w-4 h-4" /> Critical Alerts</h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">Open High and Critical alerts: suspicious logins, phishing, malicious URLs, unusual network activity</p>
          </div>
          <span className="text-xs font-bold text-red-700 dark:text-red-300">{critical.filter((c) => !c.is_acknowledged).length} unacknowledged</span>
        </div>
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {critical.length === 0 && <li className="p-5 text-center text-xs text-slate-500">{loaded ? 'No open critical alerts.' : 'Loading…'}</li>}
          {critical.map((a) => (
            <li key={a.event_id} className="px-4 py-2.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${riskBadge(a.severity)}`}>{a.severity}</span>
              <span className="font-semibold text-slate-900 dark:text-white flex-1 min-w-48">{a.threat_category}</span>
              <span className="text-slate-500 font-mono break-all">{a.user_account || a.source_ip || a.event_source}</span>
              <span className="text-slate-400 w-36 shrink-0">{parseUtc(a.timestamp).toLocaleString()}</span>
              {a.is_simulated && <SimulatedBadge />}
              {a.is_acknowledged && <span className="text-emerald-600 dark:text-emerald-400">acknowledged</span>}
              <button onClick={() => setEventId(a.event_id)} className="font-semibold text-sky-600 dark:text-sky-400 hover:underline">Investigate</button>
            </li>
          ))}
        </ul>
      </section>

      {loaded && !error && !hasEvents && (
        <div className="p-4 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-400 flex items-center justify-between gap-3">
          <span>No security events yet. Connect a data source, or run a phishing, file or network analysis, and results appear here.</span>
          <button onClick={() => onNavigateToTab('zetaris')} className="font-semibold text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap">Data sources →</button>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3.5">
        <Kpi label="Employees monitored" value={metrics?.active_employees_monitored ?? '-'} icon={<Users className="w-3.5 h-3.5" />} tint="bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400" />
        <Kpi label="Security Events" value={metrics ? metrics.total_events_analyzed.toLocaleString() : '-'} note={delta?.text} noteTone={delta?.tone} icon={<Activity className="w-3.5 h-3.5" />} tint="bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-400" />
        <Kpi label="Open Incidents" value={metrics?.open_investigations ?? '-'} icon={<AlertTriangle className="w-3.5 h-3.5" />} tint="bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400" />
        <Kpi label="Critical Events" value={metrics?.critical_events_last_24h ?? '-'} note="last 24h" icon={<ShieldAlert className="w-3.5 h-3.5" />} tint="bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400" danger={(metrics?.critical_events_last_24h ?? 0) > 0} />
        <Kpi label="Suspicious URLs" value={metrics?.suspicious_urls_total ?? '-'} icon={<Globe className="w-3.5 h-3.5" />} tint="bg-amber-50 dark:bg-amber-950 text-amber-600 dark:text-amber-400" />
        <Kpi label="Data Leak Alerts" value={metrics?.secret_leaks_total ?? '-'} icon={<KeyRound className="w-3.5 h-3.5" />} tint="bg-purple-50 dark:bg-purple-950 text-purple-600 dark:text-purple-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <div className="pb-3 border-b border-slate-100 dark:border-slate-800/80 mb-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Security Events (last 28 hours)</h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">Counts per 4-hour period, straight from the event store</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={theme === 'dark' ? '#334155' : '#f1f5f9'} />
                <XAxis dataKey="time_label" tickLine={false} axisLine={{ stroke: theme === 'dark' ? '#475569' : '#cbd5e1' }} tick={{ fill: axis, fontSize: 10 }} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: axis, fontSize: 10 }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="total_events" name="All events" stroke="#64748b" fill="#64748b" fillOpacity={0.08} strokeWidth={2} />
                <Area type="monotone" dataKey="threats" name="Risk ≥ 50" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.12} strokeWidth={2} />
                <Area type="monotone" dataKey="phishing" name="Phishing" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.12} strokeWidth={2} />
                <Area type="monotone" dataKey="network" name="Network / access" stroke="#0284c7" fill="#0284c7" fillOpacity={0.12} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="flex items-center justify-center flex-wrap gap-4 pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-600 dark:text-slate-400">
            {[['All events', 'bg-slate-500'], ['Risk ≥ 50', 'bg-rose-500'], ['Phishing', 'bg-purple-500'], ['Network / access', 'bg-sky-500']].map(([name, cls]) => (
              <div key={name} className="flex items-center gap-1.5"><span className={`w-2.5 h-2.5 rounded-full ${cls}`} /><span>{name}</span></div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-5 bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs">
          <div className="pb-3 border-b border-slate-100 dark:border-slate-800/80 mb-2">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Threat Category Distribution</h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">All stored events, grouped by detected category</p>
          </div>
          {categories.length === 0 ? (
            <p className="py-16 text-center text-xs text-slate-500">No events to classify yet.</p>
          ) : (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-2">
              <div className="w-48 h-48 relative flex items-center justify-center shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={categories} innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="count" nameKey="category">
                      {categories.map((_, i) => (
                        <Cell key={i} fill={PALETTE[i % PALETTE.length]} stroke={theme === 'dark' ? '#0f172a' : '#ffffff'} strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute text-center pointer-events-none">
                  <div className="text-lg font-bold text-slate-900 dark:text-white">{totalCategorised.toLocaleString()}</div>
                  <div className="text-[10px] font-medium text-slate-500 dark:text-slate-400">Events</div>
                </div>
              </div>
              <div className="space-y-2 text-xs flex-1 w-full sm:w-auto">
                {categories.map((c, i) => (
                  <div key={c.category} className="flex items-center justify-between gap-2 text-[11px]">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: PALETTE[i % PALETTE.length] }} />
                      <span className="text-slate-700 dark:text-slate-300 truncate">{c.category}</span>
                    </div>
                    <span className="font-bold text-slate-900 dark:text-white">{c.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="pt-2 text-[10px] text-slate-400 text-center border-t border-slate-100 dark:border-slate-800">
            {updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}, refreshes every ${REFRESH_MS / 1000}s` : 'Loading…'}
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Recent Security Alerts</h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">Latest high-priority events from every source</p>
          </div>
          <button onClick={() => onNavigateToTab('incidents')} className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1">
            <span>View All</span><ExternalLink className="w-3 h-3" />
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4">Time</th><th className="py-2.5 px-4">User / Source</th><th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">Details</th><th className="py-2.5 px-4">Risk</th><th className="py-2.5 px-4">Incident</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {alerts.length === 0 && (
                <tr><td colSpan={7} className="py-8 text-center text-slate-500">{loaded ? 'No alerts yet.' : 'Loading…'}</td></tr>
              )}
              {alerts.map((a) => (
                <tr key={a.event_id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400 whitespace-nowrap">{parseUtc(a.timestamp).toLocaleString()}</td>
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white break-all">{a.user_account || a.source_ip || a.event_source}</td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 font-medium">{a.threat_category}{a.is_simulated && <SimulatedBadge className="ml-2" />}</td>
                  <td className="py-3 px-4 text-slate-500 dark:text-slate-400 max-w-xs truncate" title={a.evidence}>{a.evidence}</td>
                  <td className="py-3 px-4"><span className={`px-2 py-0.5 rounded text-[10px] font-bold ${riskBadge(a.severity)}`}>{a.severity}</span></td>
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">{a.incident_id ?? '-'}</td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => (a.incident_id && onSelectIncident ? onSelectIncident(a.incident_id) : onNavigateToTab('incidents'))}
                      className="px-2.5 py-1 text-xs font-semibold text-sky-600 dark:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-950/60 rounded transition"
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
      {eventId && <EventInvestigation eventId={eventId} onClose={() => setEventId(null)} onChanged={() => void load()} onOpenIncident={(id) => { setEventId(null); onSelectIncident?.(id); }} />}
    </div>
  );
};
