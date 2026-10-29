import React, { useCallback, useState } from 'react';
import { Database, RefreshCw, Play, Search, Ban } from 'lucide-react';
import { api } from '../api/client';
import { Investigation, UserSession, ZetarisIngestReport, ZetarisStatus } from '../types';
import { NavTab } from '../components/layout/Sidebar';
import { useLoad } from '../hooks/useLoad';

interface Props {
  currentUser: UserSession;
  onNavigateToTab: (tab: NavTab) => void;
}

const sourceStyle: Record<string, string> = {
  auth: 'bg-indigo-50 dark:bg-indigo-950/50 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-900',
  network: 'bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900',
  email: 'bg-sky-50 dark:bg-sky-950/50 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-900',
};

const when = (iso: string | null) => (iso ? new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString() : 'never');

export const ZetarisPage: React.FC<Props> = ({ currentUser, onNavigateToTab }) => {
  const isAdmin = currentUser.role === 'Super Admin' || currentUser.role === 'Security Administrator';
  const [status, setStatus] = useState<ZetarisStatus | null>(null);
  const [report, setReport] = useState<ZetarisIngestReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [indicator, setIndicator] = useState('');
  const [result, setResult] = useState<Investigation | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [proposed, setProposed] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      setStatus(await api.getZetarisStatus());
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  useLoad(load, [load]);

  const ingest = async () => {
    setBusy(true);
    setError(null);
    try {
      setReport(await api.runZetarisIngest());
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const investigate = async (e: React.FormEvent) => {
    e.preventDefault();
    setInvestigating(true);
    setError(null);
    setProposed({});
    try {
      setResult(await api.zetarisInvestigate(indicator.trim()));
    } catch (err: any) {
      setResult(null);
      setError(err.message);
    } finally {
      setInvestigating(false);
    }
  };

  const propose = async (s: { indicator: string; reason: string }) => {
    try {
      const entry = await api.proposeBlock({ indicator: s.indicator, reason: s.reason });
      setProposed((p) => ({ ...p, [s.indicator]: entry.status === 'ACTIVE' ? 'Published' : 'Awaiting approval' }));
    } catch (err: any) {
      setProposed((p) => ({ ...p, [s.indicator]: `Refused: ${err.message}` }));
    }
  };

  const card = 'bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800';
  const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';

  return (
    <div className="space-y-6">
      <div className="pb-2 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
          <Database className="w-5 h-5 text-sky-500" /> Data Sources (Zetaris)
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Security data is read where it lives through Zetaris. Nothing is copied except the events CyberShield detects.
        </p>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>
      )}

      <section className={card + ' space-y-3'}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white">
            <span className={`w-2.5 h-2.5 rounded-full ${status?.connected ? 'bg-emerald-500' : 'bg-red-500'}`} />
            {!status ? 'Checking…' : status.connected ? 'Connected' : status.configured ? 'Not connected' : 'Not configured'}
            {status?.connected && status.latency_ms !== undefined && (
              <span className="text-xs font-normal text-slate-500">{status.latency_ms} ms</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => void load()} aria-label="Refresh status" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
            {isAdmin && (
              <button onClick={() => void ingest()} disabled={busy || !status?.connected}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
                <Play className="w-3.5 h-3.5" /> {busy ? 'Ingesting…' : 'Ingest now'}
              </button>
            )}
          </div>
        </div>
        {status?.error && <p className="text-xs text-red-600 dark:text-red-400">{status.error}</p>}
        {status?.connected && status.databases && (
          <p className="text-xs text-slate-500 dark:text-slate-400">Databases visible: {status.databases.join(', ') || 'none'}</p>
        )}

        {report && (
          <p className="text-xs text-emerald-700 dark:text-emerald-400">
            Ingest finished: {report.events_created} new events, {report.correlated_incidents} incidents correlated.
            {Object.entries(report.sources).filter(([, v]) => v.status === 'ERROR').map(([k, v]) => ` ${k}: ${v.error}`)}
          </p>
        )}

        <table className="w-full text-left text-xs">
          <thead><tr className="text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
            <th className="py-2 pr-4">Source</th><th className="py-2 pr-4">Table</th><th className="py-2 pr-4">Last run</th>
            <th className="py-2 pr-4">Status</th><th className="py-2 pr-4">Rows</th><th className="py-2">Events</th>
          </tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {(['auth', 'network', 'email'] as const).map((s) => {
              const st = status?.sources.find((x) => x.source === s);
              const table = status?.tables?.[s];
              return (
                <tr key={s}>
                  <td className="py-2 pr-4"><span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold ${sourceStyle[s]}`}>{s}</span></td>
                  <td className="py-2 pr-4 font-mono text-slate-700 dark:text-slate-300">{table ?? 'not configured'}</td>
                  <td className="py-2 pr-4 text-slate-600 dark:text-slate-400">{when(st?.last_run_at ?? null)}</td>
                  <td className="py-2 pr-4" title={st?.last_error ?? ''}>{st?.last_status ?? '-'}</td>
                  <td className="py-2 pr-4">{st?.rows_seen ?? 0}</td>
                  <td className="py-2">{st?.events_created ?? 0}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <section className={card + ' space-y-4'}>
        <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><Search className="w-4 h-4" /> Investigate an IP address or user</h2>
        <form onSubmit={investigate} className="flex gap-2">
          <input required minLength={2} value={indicator} onChange={(e) => setIndicator(e.target.value)}
            placeholder="45.155.205.233 or priya.s@enterprise-corp.com" className={field + ' flex-1 max-w-md font-mono'} />
          <button disabled={investigating || !status?.connected}
            className="px-3.5 py-1.5 bg-slate-800 dark:bg-slate-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
            {investigating ? 'Querying…' : 'Investigate'}
          </button>
        </form>

        {result && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="text-slate-500">Queried via Zetaris:</span>
              {result.sources_queried.map((s) => (
                <span key={s} className={`px-2 py-0.5 rounded-full border text-[10px] font-bold ${sourceStyle[s]}`}>{s}</span>
              ))}
              {Object.entries(result.stats).map(([k, v]) => (
                <span key={k} className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                  {k.replace(/_/g, ' ')}: <b>{v.toLocaleString()}</b>
                </span>
              ))}
            </div>

            {result.suggested_blocks.map((s) => (
              <div key={s.indicator} className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs flex items-center justify-between gap-3">
                <div>
                  <p className="font-semibold text-red-800 dark:text-red-300 font-mono">{s.indicator}</p>
                  <p className="text-slate-600 dark:text-slate-400">{s.reason}</p>
                </div>
                {proposed[s.indicator] ? (
                  <button onClick={() => onNavigateToTab('blocklist')} className="text-sky-600 dark:text-sky-400 font-semibold hover:underline whitespace-nowrap">{proposed[s.indicator]} →</button>
                ) : (
                  <button onClick={() => void propose(s)} className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold whitespace-nowrap">
                    <Ban className="w-3.5 h-3.5" /> {isAdmin ? 'Block' : 'Propose block'}
                  </button>
                )}
              </div>
            ))}

            <ol className="space-y-1.5 max-h-96 overflow-y-auto">
              {result.timeline.length === 0 && <li className="text-xs text-slate-500">No activity found in the lookback window.</li>}
              {result.timeline.map((t, i) => (
                <li key={i} className="flex items-start gap-3 text-xs">
                  <span className="font-mono text-slate-500 w-36 shrink-0">{t.time}</span>
                  <span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold shrink-0 ${sourceStyle[t.source]}`}>{t.source}</span>
                  <span className="text-slate-800 dark:text-slate-200 break-all">{t.summary}</span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </section>
    </div>
  );
};
