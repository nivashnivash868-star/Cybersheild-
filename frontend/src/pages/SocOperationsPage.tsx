import React, { useCallback, useState } from 'react';
import { Bot, UserCheck, RefreshCw, Play, Check, X, RotateCcw, Plus } from 'lucide-react';
import { api } from '../api/client';
import { AgentRun, DecisionRequest, DetectionRule, SocOverview, UserSession } from '../types';
import { useLoad } from '../hooks/useLoad';

interface Props {
  currentUser: UserSession;
  onSelectIncident: (id: string) => void;
}

const REFRESH_MS = 10000;
const when = (iso: string | null) => (iso ? new Date(/[zZ]$/.test(iso) ? iso : iso + 'Z').toLocaleTimeString() : '-');
const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800';
const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';

const prio: Record<string, string> = {
  Critical: 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border-red-200 dark:border-red-900/60',
  High: 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-900/60',
  Medium: 'bg-yellow-50 dark:bg-yellow-950/60 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900/60',
  Low: 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/60',
};
const verdictStyle: Record<string, string> = {
  TRUE_POSITIVE: 'text-red-600 dark:text-red-400', NEEDS_HUMAN: 'text-amber-600 dark:text-amber-400', FALSE_POSITIVE: 'text-emerald-600 dark:text-emerald-400',
  ESCALATED: 'text-amber-600 dark:text-amber-400', AUTO_CLOSED: 'text-slate-500', DUPLICATE: 'text-slate-500',
};
const kindLabel: Record<string, string> = { CONTAINMENT: 'Block', INCIDENT_DISPOSITION: 'Incident', DETECTION_RULE: 'Alert rule', DISABLE_ACCOUNT: 'Disable account', HOST_ISOLATION: 'Isolate host', INCIDENT_CLOSURE: 'Close incident' };

const Stat: React.FC<{ label: string; value: number | string; tone?: string }> = ({ label, value, tone }) => (
  <div><div className={`text-xl font-bold ${tone ?? 'text-slate-900 dark:text-white'}`}>{value}</div><div className="text-[11px] text-slate-500 dark:text-slate-400">{label}</div></div>
);

export const SocOperationsPage: React.FC<Props> = ({ currentUser, onSelectIncident }) => {
  const isAdmin = currentUser.role === 'Super Admin' || currentUser.role === 'Security Administrator';
  const [overview, setOverview] = useState<SocOverview | null>(null);
  const [decisions, setDecisions] = useState<DecisionRequest[]>([]);
  const [history, setHistory] = useState<DecisionRequest[]>([]);
  const [activity, setActivity] = useState<AgentRun[]>([]);
  const [tier, setTier] = useState<'L1' | 'L2'>('L2');
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ruleForm, setRuleForm] = useState({ name: '', kind: 'SUPPRESS', category: '', source_ip: '', user: '', max_risk: '' });

  const connectorFor = (action: string) => !!overview?.response_connector?.configured && overview.response_connector.actions.includes(action);

  const load = useCallback(async () => {
    try {
      const [o, d, h, a, r] = await Promise.all([
        api.getSocOverview(), api.getDecisions('PENDING'), api.getDecisions('All'), api.getSocActivity(tier), api.getRules(),
      ]);
      setOverview(o);
      setDecisions(d);
      setHistory(h.filter((x) => x.status !== 'PENDING').slice(0, 8));
      setActivity(a);
      setRules(r);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    }
  }, [tier]);

  useLoad(load, [load], { every: REFRESH_MS });

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); await load(); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };

  const createRule = (e: React.FormEvent) => {
    e.preventDefault();
    const match: Record<string, string | number> = {};
    if (ruleForm.category.trim()) match.category_contains = ruleForm.category.trim();
    if (ruleForm.source_ip.trim()) match.source_ip = ruleForm.source_ip.trim();
    if (ruleForm.user.trim()) match.user = ruleForm.user.trim();
    if (ruleForm.max_risk.trim()) match.max_risk = Number(ruleForm.max_risk);
    void act(async () => {
      const res: any = await api.createRule({ name: ruleForm.name.trim(), kind: ruleForm.kind, match });
      setNotice(res.status === 'approval_requested' ? 'Sent to a Security Administrator for approval. It becomes active only when they approve it.' : 'Rule created and active.');
      setRuleForm({ name: '', kind: 'SUPPRESS', category: '', source_ip: '', user: '', max_risk: '' });
    });
  };

  const rate = overview?.automation_rate;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">SOC Operations</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Levels 1 and 2 run on their own. Anything that blocks traffic, closes an incident or changes detection logic waits for a person.
          </p>
        </div>
        <div className="flex items-center gap-3 self-start sm:self-auto">
          {rate != null && (
            <div className="text-right"><div className="text-xl font-bold text-emerald-600 dark:text-emerald-400">{Math.round(rate * 100)}%</div><div className="text-[10px] text-slate-500">handled without a person</div></div>
          )}
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
          {isAdmin && (
            <button disabled={busy} onClick={() => void act(() => api.runSoc())} className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
              <Play className="w-3.5 h-3.5" /> Run now
            </button>
          )}
        </div>
      </div>

      {notice && <div className="p-3 rounded-lg bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-900 text-sky-800 dark:text-sky-200 text-xs">{notice}</div>}
      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>}

      <div className="grid gap-4 md:grid-cols-3">
        <div className={card + ' p-4 space-y-3'}>
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white"><Bot className="w-4 h-4 text-sky-500" /> Level 1 · Triage <span className="text-[10px] font-semibold text-sky-600 dark:text-sky-400">AUTOMATED</span></div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Monitors every alert, removes duplicates, closes noise, escalates the rest.</p>
          <div className="grid grid-cols-3 gap-3">
            <Stat label="alerts seen" value={overview?.l1.triaged ?? '-'} />
            <Stat label="auto-closed" value={(overview?.l1.auto_closed ?? 0) + (overview?.l1.duplicates ?? 0)} tone="text-emerald-600 dark:text-emerald-400" />
            <Stat label="escalated" value={overview?.l1.escalated ?? '-'} tone="text-amber-600 dark:text-amber-400" />
          </div>
        </div>
        <div className={card + ' p-4 space-y-3'}>
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white"><Bot className="w-4 h-4 text-violet-500" /> Level 2 · Investigation <span className="text-[10px] font-semibold text-sky-600 dark:text-sky-400">AUTOMATED</span></div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Correlates alerts into incidents, gathers evidence, reaches a verdict and proposes a response.</p>
          <div className="grid grid-cols-3 gap-3">
            <Stat label="investigated" value={overview?.l2.incidents_investigated ?? '-'} />
            <Stat label="true positive" value={overview?.l2.true_positive ?? '-'} tone="text-red-600 dark:text-red-400" />
            <Stat label="closed as benign" value={overview?.l2.false_positive ?? '-'} tone="text-emerald-600 dark:text-emerald-400" />
          </div>
        </div>
        <div className={card + ' p-4 space-y-3 border-amber-300 dark:border-amber-800'}>
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white"><UserCheck className="w-4 h-4 text-amber-500" /> Level 3 · Decisions <span className="text-[10px] font-semibold text-amber-600 dark:text-amber-400">HUMAN</span></div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">People approve blocks, confirm or dismiss incidents, and own detection engineering.</p>
          <div className="grid grid-cols-3 gap-3">
            <Stat label="awaiting you" value={overview?.l3.pending ?? '-'} tone={(overview?.l3.pending ?? 0) > 0 ? 'text-amber-600 dark:text-amber-400' : undefined} />
            <Stat label="decided" value={(overview?.l3.approved ?? 0) + (overview?.l3.rejected ?? 0)} />
            <Stat label="active rules" value={overview?.l3.active_rules ?? '-'} />
          </div>
        </div>
      </div>

      <section className="space-y-3">
        <h2 className="text-sm font-bold text-slate-900 dark:text-white">Waiting for a human decision</h2>
        {decisions.length === 0 && <div className={card + ' p-6 text-center text-xs text-slate-500'}>Nothing needs a decision right now.</div>}
        {decisions.map((d) => (
          <div key={d.id} className={card + ' p-4 space-y-3'}>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${prio[d.priority] ?? prio.Medium}`}>{d.priority}</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[10px] font-bold text-slate-600 dark:text-slate-300">{kindLabel[d.kind]}</span>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{d.title}</h3>
              {d.incident_id && <button onClick={() => onSelectIncident(d.incident_id!)} className="ml-auto text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline">{d.incident_id} →</button>}
            </div>
            <p className="text-xs text-slate-700 dark:text-slate-300">{d.rationale}</p>
            {d.kind === 'INCIDENT_DISPOSITION' && (
              <p className="text-[11px] text-slate-500">Approve: {d.proposal.on_approve} Reject: {d.proposal.on_reject}</p>
            )}
            {d.kind === 'CONTAINMENT' && (
              <p className="text-[11px] text-slate-500 font-mono">On approval: publish <b>{d.proposal.indicator}</b> to the blocklist feeds for {d.proposal.ttl_hours}h.</p>
            )}
            {d.kind === 'DISABLE_ACCOUNT' && (
              <p className="text-[11px] text-slate-500">
                On approval: deactivate <b>{d.proposal.account}</b> in CyberShield and sign them out.{' '}
                {connectorFor('DISABLE_ACCOUNT') ? 'A signed request also goes to your response connector to disable it in the identity provider; it counts as done only when the connector confirms.' : 'Disabling the account in your identity provider is still a manual step.'}
              </p>
            )}
            {d.kind === 'HOST_ISOLATION' && (
              <p className="text-[11px] text-slate-500">
                {connectorFor('HOST_ISOLATION')
                  ? <>On approval: a signed request to isolate <b>{d.proposal.host}</b> goes to your response connector (EDR / network access control); it counts as done only when the connector confirms.</>
                  : <>On approval: record the approval for <b>{d.proposal.host}</b>. A responder carries out the isolation in your EDR; no response connector is configured.</>}
              </p>
            )}
            {d.kind === 'INCIDENT_CLOSURE' && <p className="text-[11px] text-slate-500">On approval: close the incident as <b>{d.proposal.target_status}</b>. Requested by {d.proposal.requested_by}.</p>}
            {d.kind === 'DETECTION_RULE' && (
              <p className="text-[11px] text-slate-500 font-mono">On approval: {d.proposal.kind} rule when {JSON.stringify(d.proposal.match)}</p>
            )}
            {d.proposal.manual_actions?.length > 0 && (
              <ul className="text-[11px] text-slate-600 dark:text-slate-400 list-disc pl-4">
                {d.proposal.manual_actions.map((m: any, i: number) => <li key={i}><b>{m.type.replace('_', ' ').toLowerCase()}</b> {m.target}: {m.details}</li>)}
              </ul>
            )}
            <button onClick={() => setOpen({ ...open, [d.id]: !open[d.id] })} className="text-[11px] font-semibold text-sky-600 dark:text-sky-400 hover:underline">
              {open[d.id] ? 'Hide' : 'Show'} the agent's evidence ({d.evidence.length})
            </button>
            {open[d.id] && <ul className="text-[11px] text-slate-600 dark:text-slate-400 list-disc pl-4 space-y-0.5">{d.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>}
            <div className="flex flex-wrap items-center gap-2">
              <input value={notes[d.id] ?? ''} onChange={(e) => setNotes({ ...notes, [d.id]: e.target.value })} placeholder="Your reasoning (kept in the audit trail)" className={field + ' flex-1 min-w-48'} maxLength={500} />
              {d.requires_admin && !isAdmin ? (
                <span className="text-[11px] font-semibold text-amber-700 dark:text-amber-300">Waiting for a Security Administrator to decide: {d.kind === 'INCIDENT_CLOSURE' ? 'closing a Critical incident' : d.kind === 'DETECTION_RULE' ? 'alert rules are security configuration' : 'this affects a person or a device'}.</span>
              ) : (<>
                <button disabled={busy} onClick={() => void act(() => api.decide(d.id, 'approve', notes[d.id]))} className="flex items-center gap-1 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50"><Check className="w-3.5 h-3.5" /> Approve</button>
                <button disabled={busy} onClick={() => void act(() => api.decide(d.id, 'reject', notes[d.id]))} className="flex items-center gap-1 px-3 py-1.5 bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-100 rounded-lg text-xs font-semibold disabled:opacity-50"><X className="w-3.5 h-3.5" /> Reject</button>
              </>)}
            </div>
          </div>
        ))}
        {history.length > 0 && (
          <div className={card + ' divide-y divide-slate-100 dark:divide-slate-800'}>
            <div className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Recently decided</div>
            {history.map((h) => (
              <div key={h.id} className="px-4 py-2 text-xs flex flex-wrap gap-x-3 text-slate-700 dark:text-slate-300">
                <span className={h.status === 'APPROVED' ? 'font-bold text-emerald-600 dark:text-emerald-400' : 'font-bold text-slate-500'}>{h.status}</span>
                <span className="font-medium">{h.title}</span><span className="text-slate-500">by {h.decided_by}</span>
                {h.outcome && <span className="text-slate-500">· {h.outcome}</span>}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">What the automation did</h2>
          {(['L2', 'L1'] as const).map((t) => (
            <button key={t} onClick={() => setTier(t)} className={`px-3 py-1 rounded-lg text-xs font-semibold ${tier === t ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>{t === 'L1' ? 'Level 1 triage' : 'Level 2 investigations'}</button>
          ))}
        </div>
        <div className={card + ' divide-y divide-slate-100 dark:divide-slate-800 max-h-96 overflow-y-auto'}>
          {activity.length === 0 && <div className="p-6 text-center text-xs text-slate-500">No automated decisions yet.</div>}
          {activity.map((a) => (
            <div key={a.id} className="px-4 py-2.5 text-xs flex flex-wrap items-start gap-x-3 gap-y-1">
              <span className="font-mono text-slate-400 w-20 shrink-0">{when(a.created_at)}</span>
              <span className={`font-bold w-28 shrink-0 ${verdictStyle[a.decision] ?? ''}`}>{a.decision.replace('_', ' ')}</span>
              <span className="font-mono text-slate-600 dark:text-slate-400 shrink-0">{a.subject_id}</span>
              <span className="text-slate-700 dark:text-slate-300 flex-1 min-w-64">{a.reason}</span>
              {a.confidence != null && <span className="text-slate-400 shrink-0">{Math.round(a.confidence * 100)}%</span>}
              {a.subject_type === 'incident' && <button onClick={() => onSelectIncident(a.subject_id)} className="text-sky-600 dark:text-sky-400 font-semibold hover:underline shrink-0">Open</button>}
              {a.tier === 'L1' && (a.decision === 'AUTO_CLOSED' || a.decision === 'DUPLICATE') && (
                <button onClick={() => void act(() => api.reopenEvent(a.subject_id))} className="inline-flex items-center gap-1 text-slate-500 hover:text-sky-600 font-semibold shrink-0"><RotateCcw className="w-3 h-3" />Reopen</button>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-bold text-slate-900 dark:text-white">Alert rules (detection engineering)</h2>
        <form onSubmit={createRule} className={card + ' p-4 grid gap-3 md:grid-cols-6 items-end'}>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 md:col-span-2">Name<input required minLength={3} value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} className={field + ' w-full mt-1'} /></label>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Action
            <select value={ruleForm.kind} onChange={(e) => setRuleForm({ ...ruleForm, kind: e.target.value })} className={field + ' w-full mt-1'}><option value="SUPPRESS">Close alerts</option><option value="ESCALATE">Always escalate</option></select>
          </label>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Category contains<input value={ruleForm.category} onChange={(e) => setRuleForm({ ...ruleForm, category: e.target.value })} className={field + ' w-full mt-1'} /></label>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Source IP<input value={ruleForm.source_ip} onChange={(e) => setRuleForm({ ...ruleForm, source_ip: e.target.value })} className={field + ' w-full mt-1 font-mono'} /></label>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">User<input value={ruleForm.user} onChange={(e) => setRuleForm({ ...ruleForm, user: e.target.value })} className={field + ' w-full mt-1'} /></label>
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Max risk<input type="number" min={0} max={100} value={ruleForm.max_risk} onChange={(e) => setRuleForm({ ...ruleForm, max_risk: e.target.value })} className={field + ' w-full mt-1'} /></label>
          <div className="md:col-span-5 text-[11px] text-slate-500">Closing rules can never hide Critical alerts (risk 85+). Every rule change is audited.</div>
          <button disabled={busy} className="flex items-center justify-center gap-1.5 px-3.5 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50"><Plus className="w-3.5 h-3.5" /> {isAdmin ? 'Add rule' : 'Request rule'}</button>
        </form>
        <div className={card + ' divide-y divide-slate-100 dark:divide-slate-800'}>
          {rules.length === 0 && <div className="p-6 text-center text-xs text-slate-500">No rules yet. L2 proposes them when it keeps dismissing the same benign pattern.</div>}
          {rules.map((r) => (
            <div key={r.id} className="px-4 py-2.5 text-xs flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="font-bold w-20 shrink-0 text-slate-700 dark:text-slate-300">{r.kind === 'SUPPRESS' ? 'Close' : 'Escalate'}</span>
              <span className="font-semibold text-slate-900 dark:text-white">{r.name}</span>
              <span className="font-mono text-slate-500 flex-1 min-w-48">{JSON.stringify(r.match)}</span>
              <span className="text-slate-400">{r.hit_count} hits · by {r.created_by}</span>
              <button disabled={busy || !isAdmin} title={isAdmin ? undefined : 'Only a Security Administrator can switch rules on or off'} onClick={() => void act(() => api.toggleRule(r.id, !r.enabled))} className={`font-semibold hover:underline ${r.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>{r.enabled ? 'On' : 'Off'}</button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
