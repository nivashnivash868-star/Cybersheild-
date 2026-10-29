import React, { useCallback, useMemo, useState } from 'react';
import { Download, RefreshCw, Search } from 'lucide-react';
import { api } from '../../api/client';
import { SecurityEvent } from '../../types';
import { SimulatedBadge } from '../common/Simulated';
import { EventInvestigation } from '../investigation/EventInvestigation';
import { useLoad } from '../../hooks/useLoad';

interface Props {
  title: string;
  subtitle: string;
  /** Which of the stored events belong on this page. */
  include: (e: SecurityEvent) => boolean;
  emptyText: string;
  exportName: string;
  onOpenIncident?: (id: string) => void;
}

const RANGES: [string, number | null][] = [['Last 24 hours', 24], ['Last 7 days', 24 * 7], ['Last 30 days', 24 * 30], ['All time', null]];
const sev: Record<string, string> = {
  Critical: 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border-red-200 dark:border-red-900/60',
  High: 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-900/60',
  Medium: 'bg-yellow-50 dark:bg-yellow-950/60 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900/60',
  Low: 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/60',
};
const parseUtc = (iso: string) => new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300';

const csvCell = (v: unknown) => {
  const s = String(v ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;          // stop spreadsheet formula injection from event text
  return /[",\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
};

/** Real stored events for one area of the platform. Nothing here is sample data. */
export const EventTable: React.FC<Props> = ({ title, subtitle, include, emptyText, exportName, onOpenIncident }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [range, setRange] = useState(1);
  const [severity, setSeverity] = useState('All');
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [now, setNow] = useState(0);            // when the events were fetched; keeps the time-range filter pure

  const load = useCallback(async () => {
    try {
      setEvents(await api.getEvents({ limit: 200 }));
      setNow(Date.now());
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoaded(true);
    }
  }, []);
  useLoad(load, [load]);

  const rows = useMemo(() => {
    const hours = RANGES[range][1];
    const since = hours ? now - hours * 3600_000 : 0;
    const q = search.trim().toLowerCase();
    return events.filter((e) => include(e) && parseUtc(e.timestamp).getTime() >= since && (severity === 'All' || e.severity === severity)
      && (!q || [e.threat_category, e.user_account, e.source_ip, e.dest_ip, e.domain, e.event_source, e.evidence].some((v) => (v ?? '').toLowerCase().includes(q))));
  }, [events, include, range, severity, search, now]);

  const exportCsv = () => {
    const head = ['time_utc', 'severity', 'risk_score', 'category', 'source', 'user', 'source_ip', 'dest_ip', 'domain', 'triage', 'simulated', 'event_id'];
    const lines = [head.join(',')].concat(rows.map((e) => [e.timestamp, e.severity, e.risk_score, e.threat_category, e.event_source, e.user_account, e.source_ip, e.dest_ip, e.domain, e.triage_status, e.is_simulated ? 'yes' : 'no', e.event_id].map(csvCell).join(',')));
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = `${exportName}.csv`; a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">{title}</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{subtitle}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={exportCsv} disabled={rows.length === 0} className="flex items-center gap-2 px-3.5 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50"><Download className="w-3.5 h-3.5" /> Export CSV</button>
        </div>
      </div>

      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">Couldn't load events: {error}</div>}

      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-2 text-xs">
        <select value={range} onChange={(e) => setRange(Number(e.target.value))} className={field} aria-label="Time range">{RANGES.map(([l], i) => <option key={l} value={i}>{l}</option>)}</select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={field} aria-label="Severity">{['All', 'Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s}>{s}</option>)}</select>
        <div className="relative flex-1 min-w-48 max-w-sm"><Search className="w-4 h-4 text-slate-400 absolute left-3 top-2" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search user, address, domain, category…" className={field + ' w-full pl-9'} /></div>
        <span className="ml-auto text-slate-500">{rows.length} shown</span>
      </div>

      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time</th><th className="py-3 px-4">User / address</th><th className="py-3 px-4">Detection</th>
                <th className="py-3 px-4">Source</th><th className="py-3 px-4">Risk</th><th className="py-3 px-4">Triage</th><th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.length === 0 && <tr><td colSpan={7} className="py-10 text-center text-slate-500">{loaded ? emptyText : 'Loading…'}</td></tr>}
              {rows.map((e) => (
                <tr key={e.event_id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40">
                  <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400 whitespace-nowrap">{parseUtc(e.timestamp).toLocaleString()}</td>
                  <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white break-all">{e.user_account || e.source_ip || e.domain || '-'}{e.domain && e.user_account && <div className="font-mono text-[11px] font-normal text-sky-600 dark:text-sky-400">{e.domain}</div>}</td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300">{e.threat_category}{e.is_simulated && <SimulatedBadge className="ml-2" />}</td>
                  <td className="py-3 px-4 text-slate-500 dark:text-slate-400">{e.event_source}</td>
                  <td className="py-3 px-4"><span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${sev[e.severity]}`}>{e.severity} {e.risk_score}</span></td>
                  <td className="py-3 px-4 text-slate-500 dark:text-slate-400">{(e.triage_status ?? '').replace('_', ' ').toLowerCase()}</td>
                  <td className="py-3 px-4 text-right"><button onClick={() => setOpen(e.event_id)} className="px-2.5 py-1 font-semibold text-sky-600 dark:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-950/60 rounded">Investigate</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {open && <EventInvestigation eventId={open} onClose={() => setOpen(null)} onChanged={() => void load()} onOpenIncident={onOpenIncident ? (id) => { setOpen(null); onOpenIncident(id); } : undefined} />}
    </div>
  );
};
