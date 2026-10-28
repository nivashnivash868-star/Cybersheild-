import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Search, RefreshCw, FileDown, Send, Eye, Check, Bot } from 'lucide-react';
import { api } from '../api/client';
import { Assignable, DecisionRequest, IncidentDetail, UserSession } from '../types';
import { SimulatedBadge } from '../components/common/Simulated';
import { EventInvestigation } from '../components/investigation/EventInvestigation';

interface Props {
  currentUser: UserSession;
  selectedIncidentId?: string | null;
  onNavigateToForensics?: (id: string) => void;
  onNavigateToTab?: (tab: any) => void;
}

const STATUSES = ['New', 'Investigating', 'Contained', 'Resolved', 'False Positive'] as const;
const CLOSING = ['Resolved', 'False Positive'];
const sevStyle: Record<string, string> = {
  Critical: 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border-red-200 dark:border-red-900/60',
  High: 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-900/60',
  Medium: 'bg-yellow-50 dark:bg-yellow-950/60 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900/60',
  Low: 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/60',
};
const verdictLabel: Record<string, [string, string]> = {
  TRUE_POSITIVE: ['Likely a genuine attack', 'text-red-600 dark:text-red-400'],
  NEEDS_HUMAN: ['Needs a human judgement', 'text-amber-600 dark:text-amber-400'],
  FALSE_POSITIVE: ['Looks benign', 'text-emerald-600 dark:text-emerald-400'],
};
const when = (iso?: string | null) => (iso ? new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z').toLocaleString() : '-');
const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800';
const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';

export const IncidentResponsePage: React.FC<Props> = ({ currentUser, selectedIncidentId, onNavigateToForensics, onNavigateToTab }) => {
  const isAdmin = currentUser.role === 'Super Admin' || currentUser.role === 'Security Administrator';
  const [incidents, setIncidents] = useState<IncidentDetail[]>([]);
  const [activeId, setActiveId] = useState<string | null>(selectedIncidentId ?? null);
  const [people, setPeople] = useState<Assignable[]>([]);
  const [decisions, setDecisions] = useState<DecisionRequest[]>([]);
  const [filter, setFilter] = useState<'open' | 'all'>('open');
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [note, setNote] = useState('');
  const [closing, setClosing] = useState<{ status: string; comment: string } | null>(null);
  const [eventId, setEventId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [list, staff, pending] = await Promise.all([api.getIncidents({ search: search || undefined }), api.getAssignable(), api.getDecisions('PENDING')]);
      setIncidents(list);
      setPeople(staff);
      setDecisions(pending);
      setActiveId((cur) => (cur && list.some((i) => i.incident_id === cur) ? cur : selectedIncidentId && list.some((i) => i.incident_id === selectedIncidentId) ? selectedIncidentId : list[0]?.incident_id ?? null));
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoaded(true);
    }
  }, [search, selectedIncidentId]);

  useEffect(() => { void load(); }, [load]);

  const visible = useMemo(() => incidents.filter((i) => filter === 'all' || !['Resolved', 'False Positive'].includes(i.status)), [incidents, filter]);
  const inc = incidents.find((i) => i.incident_id === activeId) ?? null;
  const analysis = useMemo(() => { try { return inc?.l2_analysis ? JSON.parse(inc.l2_analysis) : null; } catch { return null; } }, [inc]);
  const myDecisions = decisions.filter((d) => d.incident_id === inc?.incident_id);
  const allSimulated = !!inc && inc.events.length > 0 && inc.events.every((e) => e.is_simulated);

  const act = async (fn: () => Promise<any>, ok?: string) => {
    setBusy(true);
    setError(null);
    try {
      const res = await fn();
      setNotice(res?.message ?? ok ?? null);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const changeStatus = (status: string) => {
    if (!inc || status === inc.status) return;
    if (CLOSING.includes(status)) setClosing({ status, comment: '' });
    else void act(() => api.updateIncidentStatus(inc.incident_id, { status }), `Status is now ${status}.`);
  };

  const exportReport = async () => {
    if (!inc) return;
    try {
      const text = await api.exportIncidentReportText(inc.incident_id);
      const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${inc.incident_id}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) { setError(e.message); }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Incident Management</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Investigate, assign, annotate and resolve. Closing a Critical incident needs an administrator.</p>
        </div>
        <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
      </div>

      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>}
      {notice && <div className="p-3 rounded-lg bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-900 text-sky-800 dark:text-sky-200 text-xs">{notice}</div>}

      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <aside className={card + ' overflow-hidden self-start'}>
          <div className="p-3 space-y-2 border-b border-slate-100 dark:border-slate-800">
            <div className="relative"><Search className="w-4 h-4 text-slate-400 absolute left-3 top-2" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search incidents…" className={field + ' w-full pl-9'} /></div>
            <div className="flex gap-1.5 text-xs font-semibold">
              {(['open', 'all'] as const).map((f) => <button key={f} onClick={() => setFilter(f)} className={`px-2.5 py-1 rounded-lg ${filter === f ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>{f === 'open' ? 'Open' : 'All'}</button>)}
            </div>
          </div>
          <ul className="max-h-[70vh] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
            {visible.length === 0 && <li className="p-6 text-center text-xs text-slate-500">{loaded ? 'No incidents.' : 'Loading…'}</li>}
            {visible.map((i) => (
              <li key={i.incident_id}>
                <button onClick={() => { setActiveId(i.incident_id); setNotice(null); setClosing(null); }}
                  className={`w-full text-left p-3 text-xs hover:bg-slate-50 dark:hover:bg-slate-800/50 ${i.incident_id === activeId ? 'bg-sky-50 dark:bg-sky-950/30' : ''}`}>
                  <div className="flex items-center gap-2"><span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${sevStyle[i.severity]}`}>{i.severity}</span><span className="text-slate-500">{i.status}</span>{i.needs_human && <span className="ml-auto text-[10px] font-bold text-amber-600 dark:text-amber-400">NEEDS YOU</span>}</div>
                  <div className="mt-1 font-semibold text-slate-900 dark:text-white line-clamp-2">{i.title}</div>
                  <div className="font-mono text-[10px] text-slate-400 mt-0.5">{i.incident_id}</div>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        {!inc ? <div className={card + ' p-10 text-center text-sm text-slate-500'}>{loaded ? 'Select an incident, or none are open.' : 'Loading…'}</div> : (
          <div className="space-y-4 min-w-0">
            <section className={card + ' p-4 space-y-3'}>
              <div className="flex flex-wrap items-start gap-2">
                <span className={`px-2 py-0.5 rounded border text-xs font-bold ${sevStyle[inc.severity]}`}>{inc.severity}</span>
                <h2 className="text-base font-bold text-slate-900 dark:text-white flex-1 min-w-48">{inc.title}</h2>
                {allSimulated && <SimulatedBadge />}
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400">{inc.description}</p>
              <div className="flex flex-wrap items-center gap-4 text-xs">
                <label className="flex items-center gap-2 font-semibold text-slate-700 dark:text-slate-300">Status
                  <select disabled={busy} value={inc.status} onChange={(e) => changeStatus(e.target.value)} className={field}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
                </label>
                <label className="flex items-center gap-2 font-semibold text-slate-700 dark:text-slate-300">Assigned to
                  <select disabled={busy} value={people.some((p) => p.full_name === inc.assigned_analyst) ? inc.assigned_analyst : ''}
                    onChange={(e) => e.target.value && void act(() => api.assignIncidentAnalyst(inc.incident_id, e.target.value), `Assigned to ${e.target.value}.`)} className={field}>
                    <option value="">{inc.assigned_analyst === 'Unassigned' ? 'Unassigned' : inc.assigned_analyst}</option>
                    {people.map((p) => <option key={p.id} value={p.full_name}>{p.full_name} ({p.role})</option>)}
                  </select>
                </label>
                <span className="text-slate-500">Risk <b className="text-slate-800 dark:text-slate-200">{inc.risk_score}</b>/100 · opened {when(inc.created_at)}</span>
                <span className="ml-auto flex gap-3">
                  {onNavigateToForensics && <button onClick={() => onNavigateToForensics(inc.incident_id)} className="font-semibold text-sky-600 dark:text-sky-400 hover:underline">Forensics</button>}
                  <button onClick={() => void exportReport()} className="flex items-center gap-1 font-semibold text-sky-600 dark:text-sky-400 hover:underline"><FileDown className="w-3.5 h-3.5" />Report</button>
                </span>
              </div>
              {closing && (
                <div className="p-3 rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 space-y-2 text-xs">
                  <p className="font-semibold text-amber-900 dark:text-amber-200">Close as “{closing.status}”{inc.severity === 'Critical' && !isAdmin ? ': this sends a request to an administrator.' : '.'}</p>
                  <textarea value={closing.comment} onChange={(e) => setClosing({ ...closing, comment: e.target.value })} rows={2} placeholder="What was found and done? (required, kept in the record)" className={field + ' w-full'} />
                  <div className="flex gap-2">
                    <button disabled={busy || closing.comment.trim().length < 5} onClick={() => { const c = closing; setClosing(null); void act(() => api.updateIncidentStatus(inc.incident_id, { status: c.status, comment: c.comment.trim() })); }}
                      className="px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg font-semibold disabled:opacity-50">{inc.severity === 'Critical' && !isAdmin ? 'Request closure' : 'Close incident'}</button>
                    <button onClick={() => setClosing(null)} className="px-3 py-1.5 text-slate-600 dark:text-slate-300">Cancel</button>
                  </div>
                </div>
              )}
            </section>

            <section className={card + ' p-4 space-y-3'}>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><Bot className="w-4 h-4 text-violet-500" /> AI risk assessment <span className="text-[10px] font-semibold text-sky-600 dark:text-sky-400">AUTOMATED · LEVEL 2</span></h3>
              {!inc.l2_verdict ? <p className="text-xs text-slate-500">{inc.l2_status === 'PENDING' ? 'Investigation in progress…' : 'No automated assessment for this incident.'}</p> : (
                <>
                  <p className="text-xs"><b className={verdictLabel[inc.l2_verdict][1]}>{verdictLabel[inc.l2_verdict][0]}</b> <span className="text-slate-500">· confidence {Math.round((inc.l2_confidence ?? 0) * 100)}%</span></p>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{inc.l2_summary}</p>
                  {analysis?.kill_chain && Object.keys(analysis.kill_chain).length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      {Object.entries<string[]>(analysis.kill_chain).map(([stage, techniques], i, all) => (
                        <React.Fragment key={stage}>
                          <span className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200"><b>{stage}</b>{techniques.length > 0 && <span className="text-slate-500"> · {techniques.join(', ')}</span>}</span>
                          {i < all.length - 1 && <span className="text-slate-400">→</span>}
                        </React.Fragment>
                      ))}
                    </div>
                  )}
                  {analysis?.steps && (
                    <details className="text-xs"><summary className="cursor-pointer font-semibold text-sky-600 dark:text-sky-400">How the agent reached this ({analysis.steps.length} steps)</summary>
                      <ol className="mt-2 space-y-1 list-decimal pl-5 text-slate-600 dark:text-slate-400">{analysis.steps.map((s: any, i: number) => <li key={i}><b className="text-slate-800 dark:text-slate-200">{s.step}:</b> {s.finding}</li>)}</ol>
                    </details>
                  )}
                </>
              )}
              {myDecisions.length > 0 && (
                <div className="p-3 rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-xs space-y-1">
                  <p className="font-semibold text-amber-900 dark:text-amber-200">{myDecisions.length} decision(s) waiting for a person</p>
                  <ul className="list-disc pl-4 text-slate-700 dark:text-slate-300">{myDecisions.map((d) => <li key={d.id}>{d.title}{d.requires_admin && <span className="text-amber-700 dark:text-amber-400"> (administrator)</span>}</li>)}</ul>
                  {onNavigateToTab && <button onClick={() => onNavigateToTab('soc_ops')} className="font-semibold text-sky-600 dark:text-sky-400 hover:underline">Review in SOC Operations →</button>}
                </div>
              )}
            </section>

            <section className={card + ' p-4 space-y-2'}>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Alerts in this incident ({inc.events.length})</h3>
              <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                {[...inc.events].sort((a, b) => a.timestamp.localeCompare(b.timestamp)).map((e) => (
                  <li key={e.event_id} className="py-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                    <span className="font-mono text-slate-400 w-40 shrink-0">{when(e.timestamp)}</span>
                    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${sevStyle[e.severity]}`}>{e.severity}</span>
                    <span className="font-medium text-slate-800 dark:text-slate-200 flex-1 min-w-40">{e.threat_category}</span>
                    {e.is_simulated && <SimulatedBadge />}
                    {e.is_acknowledged && <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400"><Check className="w-3 h-3" />acknowledged</span>}
                    <button onClick={() => setEventId(e.event_id)} className="inline-flex items-center gap-1 font-semibold text-sky-600 dark:text-sky-400 hover:underline"><Eye className="w-3.5 h-3.5" />Investigate</button>
                  </li>
                ))}
              </ul>
            </section>

            <div className="grid gap-4 md:grid-cols-2">
              <section className={card + ' p-4 space-y-2'}>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Investigation notes</h3>
                <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) { const n = note.trim(); setNote(''); void act(() => api.addIncidentNote(inc.incident_id, { note_text: n }), 'Note added.'); } }} className="flex gap-2">
                  <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…" className={field + ' flex-1'} maxLength={5000} />
                  <button disabled={busy || !note.trim()} aria-label="Add note" className="px-3 bg-sky-600 hover:bg-sky-700 text-white rounded-lg disabled:opacity-50"><Send className="w-3.5 h-3.5" /></button>
                </form>
                <ul className="space-y-2 max-h-64 overflow-y-auto">
                  {inc.notes.length === 0 && <li className="text-xs text-slate-500">No notes yet.</li>}
                  {[...inc.notes].reverse().map((n) => <li key={n.id} className="text-xs"><div className="text-slate-400">{n.analyst_name} · {when(n.created_at)}</div><div className="text-slate-700 dark:text-slate-300">{n.note_text}</div></li>)}
                </ul>
              </section>
              <section className={card + ' p-4 space-y-2'}>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Response actions</h3>
                <ul className="space-y-2 max-h-72 overflow-y-auto">
                  {inc.actions.length === 0 && <li className="text-xs text-slate-500">Nothing has been done yet. Proposed actions wait in SOC Operations.</li>}
                  {inc.actions.map((a) => <li key={a.id} className="text-xs"><div className="font-semibold text-slate-800 dark:text-slate-200">{a.action_type.replace('_', ' ')} · <span className="font-mono">{a.target}</span></div><div className="text-slate-500">{a.status.replace(/_/g, ' ')}{a.executed_by ? ` by ${a.executed_by}` : ''} · {a.details}</div></li>)}
                </ul>
              </section>
            </div>

            {inc.evidence_items.length > 0 && (
              <section className={card + ' p-4 space-y-2'}>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Evidence</h3>
                <ul className="space-y-1 text-xs">{inc.evidence_items.slice(0, 12).map((e, i) => <li key={i} className="flex flex-wrap gap-x-3"><span className="font-semibold w-24 text-slate-700 dark:text-slate-300">{e.evidence_type}</span><span className="font-mono break-all text-slate-800 dark:text-slate-200">{e.evidence_value}</span><span className="text-slate-400">{e.provenance}</span></li>)}</ul>
              </section>
            )}
          </div>
        )}
      </div>
      {eventId && <EventInvestigation eventId={eventId} onClose={() => setEventId(null)} onChanged={() => void load()} onOpenIncident={(id) => { setEventId(null); setActiveId(id); }} />}
    </div>
  );
};
