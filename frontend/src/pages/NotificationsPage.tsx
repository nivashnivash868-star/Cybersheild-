import React, { useCallback, useEffect, useState } from 'react';
import { Search, RefreshCw, RotateCcw } from 'lucide-react';
import { api } from '../api/client';
import { NotificationDelivery, UserSession } from '../types';

interface Props {
  currentUser?: UserSession;
}

const STATUSES = ['All', 'QUEUED', 'SENT', 'FAILED', 'NOT_CONFIGURED', 'SUPPRESSED_DUPLICATE'] as const;
const CHANNELS = ['All', 'EMAIL', 'SMS'] as const;

const statusStyle: Record<string, string> = {
  SENT: 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
  QUEUED: 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-400 border-sky-200 dark:border-sky-800',
  SENDING: 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-400 border-sky-200 dark:border-sky-800',
  FAILED: 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900',
  NOT_CONFIGURED: 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-900',
  SUPPRESSED_DUPLICATE: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
};

const when = (iso?: string | null) => (iso ? new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z').toLocaleString() : '-');

export const NotificationsPage: React.FC<Props> = ({ currentUser }) => {
  const isAdmin = currentUser?.role === 'Super Admin' || currentUser?.role === 'Security Administrator';
  const [rows, setRows] = useState<NotificationDelivery[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [status, setStatus] = useState<(typeof STATUSES)[number]>('All');
  const [channel, setChannel] = useState<(typeof CHANNELS)[number]>('All');
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const [list, sum] = await Promise.all([
        api.getNotificationDeliveries({ status, channel, q: search.trim(), limit: 100 }), api.getDeliverySummary(),
      ]);
      setRows(list);
      setSummary(sum);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoaded(true);
    }
  }, [status, channel, search]);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 15000);
    return () => clearInterval(id);
  }, [load]);

  const retry = async (id: number) => {
    try { await api.retryDelivery(id); await load(); } catch (e: any) { setError(e.message); }
  };

  const problems = (summary.FAILED ?? 0) + (summary.NOT_CONFIGURED ?? 0);
  const btn = (active: boolean) => `px-3 py-1.5 rounded-lg transition ${active ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Notifications</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Every alert the platform tried to send. “Sent” means the mail server or SMS provider accepted it.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search recipient or title…"
              className="pl-9 pr-3 py-1.5 text-xs bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white w-64" />
          </div>
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
        </div>
      </div>

      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>}

      {problems > 0 && (
        <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 text-xs text-amber-800 dark:text-amber-300">
          {summary.NOT_CONFIGURED ?? 0} alert(s) could not be sent because no email/SMS transport is configured, and {summary.FAILED ?? 0} failed.
          Configure SMTP or Twilio in the server settings, then retry them here.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-semibold">
        <div className="flex items-center gap-1.5">
          {CHANNELS.map((c) => <button key={c} onClick={() => setChannel(c)} className={btn(channel === c)}>{c === 'All' ? 'All channels' : c}</button>)}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {STATUSES.map((s) => (
            <button key={s} onClick={() => setStatus(s)} className={btn(status === s)}>
              {s === 'All' ? 'All' : s.replace('_', ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase())}
              {s !== 'All' && summary[s] ? <span className="ml-1 opacity-70">{summary[s]}</span> : null}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Queued</th><th className="py-3 px-4">Recipient</th><th className="py-3 px-4">Message</th>
                <th className="py-3 px-4">Channel</th><th className="py-3 px-4">Status</th><th className="py-3 px-4">Sent</th><th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.length === 0 && <tr><td colSpan={7} className="py-8 text-center text-slate-500">{loaded ? 'No notifications match.' : 'Loading…'}</td></tr>}
              {rows.map((n) => (
                <tr key={n.id}>
                  <td className="py-3 px-4 font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">{when(n.sent_at)}</td>
                  <td className="py-3 px-4 text-slate-900 dark:text-white break-all">{n.recipient_address}<div className="text-[10px] text-slate-400">{n.recipient_type.replace('_', ' ').toLowerCase()}</div></td>
                  <td className="py-3 px-4 text-slate-700 dark:text-slate-300 max-w-md">
                    <div className="font-medium">{n.title}</div>
                    <div className="text-slate-500 truncate" title={n.body_preview}>{n.body_preview}</div>
                    {n.last_error && <div className="text-red-600 dark:text-red-400 mt-0.5">{n.last_error}</div>}
                  </td>
                  <td className="py-3 px-4 font-medium text-slate-600 dark:text-slate-400">{n.channel}</td>
                  <td className="py-3 px-4"><span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold ${statusStyle[n.delivery_status] ?? ''}`}>{n.delivery_status.replace('_', ' ')}</span></td>
                  <td className="py-3 px-4 font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">{when(n.dispatched_at)}</td>
                  <td className="py-3 px-4 text-right">
                    {isAdmin && (n.delivery_status === 'FAILED' || n.delivery_status === 'NOT_CONFIGURED') && (
                      <button onClick={() => void retry(n.id)} className="inline-flex items-center gap-1 text-sky-600 dark:text-sky-400 font-semibold hover:underline"><RotateCcw className="w-3.5 h-3.5" />Retry</button>
                    )}
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
