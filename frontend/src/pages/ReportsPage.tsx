import React, { useCallback, useEffect, useState } from 'react';
import { Download, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { DashboardMetrics, IncidentDetail, SecurityEvent, SocOverview } from '../types';
import { SimulatedBanner } from '../components/common/Simulated';

const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5';

const count = <T,>(rows: T[], key: (r: T) => string) =>
  Object.entries(rows.reduce<Record<string, number>>((acc, r) => { const k = key(r) || 'Unknown'; acc[k] = (acc[k] ?? 0) + 1; return acc; }, {})).sort((a, b) => b[1] - a[1]);

/** Reports computed from stored data. The downloadable summary contains the same numbers shown here and nothing else. */
export const ReportsPage: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [soc, setSoc] = useState<SocOverview | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<IncidentDetail[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const [m, s, e, i] = await Promise.all([api.getDashboardMetrics(), api.getSocOverview(), api.getEvents({ limit: 200 }), api.getIncidents()]);
      setMetrics(m); setSoc(s); setEvents(e); setIncidents(i); setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoaded(true);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const bySeverity = count(events, (e) => e.severity);
  const byCategory = count(events, (e) => e.threat_category).slice(0, 8);
  const byStatus = count(incidents, (i) => i.status);
  const bySource = count(events, (e) => e.event_source).slice(0, 6);
  const simulated = metrics?.simulated_events_total ?? 0;

  const download = () => {
    if (!metrics || !soc) return;
    const lines = [
      '# CYBERSHIELD AI security summary', '', `Generated ${new Date().toISOString()} from stored data.`,
      simulated > 0 ? `\n> ${simulated} of ${metrics.total_events_analyzed} events are SIMULATED test data.\n` : '',
      '## Totals', `- Events analysed: ${metrics.total_events_analyzed}`, `- Events in the last 24 hours: ${metrics.events_last_24h}`,
      `- Open investigations: ${metrics.open_investigations}`, `- Critical incidents: ${metrics.critical_incidents}`,
      '', '## Automation', `- Level 1 triaged ${soc.l1.triaged} alerts: ${soc.l1.auto_closed + soc.l1.duplicates} closed automatically, ${soc.l1.escalated} escalated`,
      `- Level 2 investigated ${soc.l2.incidents_investigated} incidents: ${soc.l2.true_positive} true positive, ${soc.l2.needs_human} need a human, ${soc.l2.false_positive} benign`,
      `- Level 3 decisions: ${soc.l3.pending} pending, ${soc.l3.approved} approved, ${soc.l3.rejected} rejected`,
      soc.automation_rate != null ? `- Share handled without a person: ${Math.round(soc.automation_rate * 100)}%` : '',
      '', '## Events by severity', ...bySeverity.map(([k, v]) => `- ${k}: ${v}`),
      '', '## Top detections', ...byCategory.map(([k, v]) => `- ${k}: ${v}`),
      '', '## Incidents by status', ...byStatus.map(([k, v]) => `- ${k}: ${v}`),
      '', `_Based on the most recent ${events.length} events and ${incidents.length} incidents._`,
    ].filter((l) => l !== undefined);
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/markdown' }));
    const a = document.createElement('a');
    a.href = url; a.download = `cybershield-summary-${new Date().toISOString().slice(0, 10)}.md`; a.click(); URL.revokeObjectURL(url);
  };

  const Bars: React.FC<{ rows: [string, number][]; tone: string }> = ({ rows, tone }) => {
    const max = Math.max(1, ...rows.map((r) => r[1]));
    return (
      <ul className="space-y-2">
        {rows.length === 0 && <li className="text-xs text-slate-500">{loaded ? 'No data yet.' : 'Loading…'}</li>}
        {rows.map(([k, v]) => (
          <li key={k} className="text-xs"><div className="flex justify-between text-slate-700 dark:text-slate-300"><span className="truncate pr-2">{k}</span><b>{v}</b></div>
            <div className="h-1.5 rounded bg-slate-100 dark:bg-slate-800 mt-1"><div className={`h-1.5 rounded ${tone}`} style={{ width: `${(v / max) * 100}%` }} /></div></li>
        ))}
      </ul>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Reports</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">A summary of what is stored right now: events, incidents and what the automation did</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={download} disabled={!metrics || !soc} className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50"><Download className="w-3.5 h-3.5" /> Download summary</button>
        </div>
      </div>
      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">Couldn't load the report: {error}</div>}
      {metrics && <SimulatedBanner simulated={simulated} total={metrics.total_events_analyzed} />}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        {[['Events analysed', metrics?.total_events_analyzed], ['Last 24 hours', metrics?.events_last_24h], ['Open investigations', metrics?.open_investigations], ['Handled without a person', soc?.automation_rate != null ? `${Math.round(soc.automation_rate * 100)}%` : '-']].map(([label, value]) => (
          <div key={String(label)} className={card}><div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">{label}</div><div className="text-2xl font-bold text-slate-900 dark:text-white">{value ?? '-'}</div></div>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <section className={card + ' space-y-3'}><h2 className="text-sm font-bold text-slate-900 dark:text-white">Events by severity</h2><Bars rows={bySeverity} tone="bg-red-500" /></section>
        <section className={card + ' space-y-3'}><h2 className="text-sm font-bold text-slate-900 dark:text-white">Top detections</h2><Bars rows={byCategory} tone="bg-violet-500" /></section>
        <section className={card + ' space-y-3'}><h2 className="text-sm font-bold text-slate-900 dark:text-white">Incidents by status</h2><Bars rows={byStatus} tone="bg-sky-500" /></section>
        <section className={card + ' space-y-3'}><h2 className="text-sm font-bold text-slate-900 dark:text-white">Where events come from</h2><Bars rows={bySource} tone="bg-emerald-500" /></section>
      </div>
      <p className="text-[11px] text-slate-500">Charts use the most recent {events.length} events and {incidents.length} incidents.</p>
    </div>
  );
};
