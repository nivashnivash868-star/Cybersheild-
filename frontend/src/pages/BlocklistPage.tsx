import React, { useCallback, useEffect, useState } from 'react';
import { Ban, Check, X, Undo2, Plus, KeyRound, Copy, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { BlocklistEntry, FeedTokenInfo, UserSession } from '../types';

interface Props {
  currentUser: UserSession;
}

const STATUS_FILTERS = ['All', 'PENDING_APPROVAL', 'ACTIVE', 'EXPIRED', 'REVOKED', 'REJECTED'] as const;

const statusStyle: Record<string, string> = {
  PENDING_APPROVAL: 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-900',
  ACTIVE: 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900',
  EXPIRED: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
  REVOKED: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
  REJECTED: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
};

const fmt = (iso: string | null) => (iso ? new Date(iso + 'Z').toLocaleString() : '-');

export const BlocklistPage: React.FC<Props> = ({ currentUser }) => {
  const isAdmin = currentUser.role === 'Super Admin' || currentUser.role === 'Security Administrator';
  const [filter, setFilter] = useState<(typeof STATUS_FILTERS)[number]>('All');
  const [entries, setEntries] = useState<BlocklistEntry[]>([]);
  const [feeds, setFeeds] = useState<FeedTokenInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [indicator, setIndicator] = useState('');
  const [reason, setReason] = useState('');
  const [ttl, setTtl] = useState(24);

  const [feedName, setFeedName] = useState('');
  const [issued, setIssued] = useState<{ name: string; token: string; urls: Record<string, string> } | null>(null);

  const load = useCallback(async () => {
    try {
      setEntries(await api.getBlocklist(filter));
      if (isAdmin) setFeeds(await api.getFeedTokens());
      setError(null);
    } catch (e: any) {
      setError(e.message);
    }
  }, [filter, isAdmin]);

  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const propose = (e: React.FormEvent) => {
    e.preventDefault();
    void act(async () => {
      await api.proposeBlock({ indicator: indicator.trim(), reason: reason.trim(), ttl_hours: ttl });
      setIndicator('');
      setReason('');
    });
  };

  const activeFeeds = feeds.filter((f) => !f.revoked_at);
  const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';

  return (
    <div className="space-y-6">
      <div className="pb-2 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
          <Ban className="w-5 h-5 text-red-500" /> Blocklist
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Approved indicators are published to the feeds your firewall or DNS sinkhole pulls. A block takes effect
          when a consumer fetches the feed, not when it is approved.
        </p>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">
          {error}
        </div>
      )}

      <form onSubmit={propose} className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 grid gap-3 md:grid-cols-[2fr_3fr_auto_auto] items-end">
        <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
          IP, CIDR, domain or URL
          <input required value={indicator} onChange={(e) => setIndicator(e.target.value)} placeholder="45.155.205.233" className={field + ' w-full mt-1 font-mono'} />
        </label>
        <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
          Reason (kept in the audit trail)
          <input required minLength={5} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="C2 beacon seen on INC-2026-0042" className={field + ' w-full mt-1'} />
        </label>
        <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
          Expires after
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))} className={field + ' w-full mt-1'}>
            <option value={1}>1 hour</option>
            <option value={24}>24 hours</option>
            <option value={168}>7 days</option>
            <option value={720}>30 days</option>
          </select>
        </label>
        <button disabled={busy} className="flex items-center justify-center gap-1.5 px-3.5 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
          <Plus className="w-3.5 h-3.5" /> {isAdmin ? 'Block now' : 'Propose block'}
        </button>
      </form>
      {!isAdmin && (
        <p className="text-[11px] text-slate-500 dark:text-slate-400 -mt-4">
          Analyst proposals wait for an administrator to approve them. Private ranges, overly broad ranges and well-known
          domains are always refused.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 text-xs font-semibold">
        {STATUS_FILTERS.map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg transition ${filter === f ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
            {f === 'All' ? 'All' : f.replace('_', ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase())}
          </button>
        ))}
        <button onClick={() => void load()} aria-label="Refresh" className="ml-auto p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
      </div>

      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Indicator</th><th className="py-3 px-4">Reason</th><th className="py-3 px-4">Proposed by</th>
                <th className="py-3 px-4">Status</th><th className="py-3 px-4">Expires</th><th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {entries.length === 0 && (
                <tr><td colSpan={6} className="py-8 text-center text-slate-500">Nothing here yet.</td></tr>
              )}
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="py-3 px-4 font-mono text-slate-900 dark:text-white break-all">
                    {e.value}<span className="ml-2 text-[10px] text-slate-400">{e.indicator_type}</span>
                  </td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 max-w-xs">{e.reason}{e.incident_id ? ` (${e.incident_id})` : ''}</td>
                  <td className="py-3 px-4 text-slate-600 dark:text-slate-400">{e.proposed_by}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold ${statusStyle[e.status]}`}>{e.status.replace('_', ' ')}</span>
                  </td>
                  <td className="py-3 px-4 text-slate-600 dark:text-slate-400">{fmt(e.expires_at)}</td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    {isAdmin && e.status === 'PENDING_APPROVAL' && (
                      <>
                        <button disabled={busy} onClick={() => void act(() => api.decideBlock(e.id, 'approve'))} className="inline-flex items-center gap-1 px-2 py-1 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/50 rounded font-semibold"><Check className="w-3.5 h-3.5" />Approve</button>
                        <button disabled={busy} onClick={() => void act(() => api.decideBlock(e.id, 'reject'))} className="inline-flex items-center gap-1 px-2 py-1 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded font-semibold"><X className="w-3.5 h-3.5" />Reject</button>
                      </>
                    )}
                    {isAdmin && e.status === 'ACTIVE' && (
                      <button disabled={busy} onClick={() => void act(() => api.decideBlock(e.id, 'revoke'))} className="inline-flex items-center gap-1 px-2 py-1 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 rounded font-semibold"><Undo2 className="w-3.5 h-3.5" />Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {isAdmin && (
        <section className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><KeyRound className="w-4 h-4" /> Feed consumers</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Each firewall or DNS sinkhole gets its own credential. {activeFeeds.length === 0
                ? 'None registered, so nothing is enforcing these blocks yet.'
                : `${activeFeeds.filter((f) => f.last_fetched_at).length} of ${activeFeeds.length} have pulled a feed.`}
            </p>
          </div>

          <form className="flex gap-2" onSubmit={(e) => {
            e.preventDefault();
            void act(async () => { setIssued(await api.createFeedToken(feedName.trim())); setFeedName(''); });
          }}>
            <input required minLength={2} value={feedName} onChange={(e) => setFeedName(e.target.value)} placeholder="e.g. edge-firewall-01" className={field + ' flex-1 max-w-xs'} />
            <button disabled={busy} className="px-3.5 py-1.5 bg-slate-800 dark:bg-slate-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">Create credential</button>
          </form>

          {issued && (
            <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 text-xs space-y-2">
              <p className="font-semibold text-amber-800 dark:text-amber-300">Copy this token now for “{issued.name}”. It is not shown again.</p>
              <div className="flex items-center gap-2">
                <code className="font-mono break-all flex-1 text-slate-900 dark:text-white">{issued.token}</code>
                <button onClick={() => void navigator.clipboard.writeText(issued.token)} aria-label="Copy token" className="p-1.5 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded"><Copy className="w-4 h-4" /></button>
              </div>
              <ul className="font-mono text-[11px] text-slate-600 dark:text-slate-400 space-y-0.5">
                {Object.entries(issued.urls).map(([k, v]) => <li key={k}>{k}: {v}</li>)}
              </ul>
              <p className="text-slate-600 dark:text-slate-400">Send it as <code>Authorization: Bearer &lt;token&gt;</code>, or as the password in HTTP Basic auth.</p>
            </div>
          )}

          <table className="w-full text-left text-xs">
            <thead><tr className="text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]"><th className="py-2 pr-4">Name</th><th className="py-2 pr-4">Last pulled</th><th className="py-2 pr-4">From</th><th className="py-2 pr-4">Status</th><th /></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {feeds.map((f) => (
                <tr key={f.id}>
                  <td className="py-2 pr-4 font-semibold text-slate-900 dark:text-white">{f.name}</td>
                  <td className="py-2 pr-4 text-slate-600 dark:text-slate-400">{f.last_fetched_at ? fmt(f.last_fetched_at) : 'never'}</td>
                  <td className="py-2 pr-4 font-mono text-slate-600 dark:text-slate-400">{f.last_fetched_ip ?? '-'}</td>
                  <td className="py-2 pr-4">{f.revoked_at ? 'Revoked' : 'Active'}</td>
                  <td className="py-2 text-right">{!f.revoked_at && <button disabled={busy} onClick={() => void act(() => api.revokeFeedToken(f.id))} className="text-red-600 dark:text-red-400 font-semibold hover:underline">Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
};
