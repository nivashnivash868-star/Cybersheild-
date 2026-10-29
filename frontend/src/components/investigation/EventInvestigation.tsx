import React, { useState } from 'react';
import { X, Check, ExternalLink } from 'lucide-react';
import { api } from '../../api/client';
import { EventDetail, ThreatIntelResult } from '../../types';
import { SimulatedBadge } from '../common/Simulated';
import { useLoad } from '../../hooks/useLoad';

const sev: Record<string, string> = {
  Critical: 'text-red-600 dark:text-red-400', High: 'text-amber-600 dark:text-amber-400',
  Medium: 'text-yellow-600 dark:text-yellow-400', Low: 'text-emerald-600 dark:text-emerald-400',
};
const when = (iso: string) => new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z').toLocaleString();

interface Props {
  eventId: string;
  onClose: () => void;
  onOpenIncident?: (id: string) => void;
  onChanged?: () => void;
}

/** Threat investigation for one alert: the evidence, how automation treated it, what else involves the same entities. */
export const EventInvestigation: React.FC<Props> = ({ eventId, onClose, onOpenIncident, onChanged }) => {
  const [d, setD] = useState<EventDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [intel, setIntel] = useState<Record<string, ThreatIntelResult | string>>({});

  const load = () => api.getEventDetail(eventId).then(setD).catch((e) => setError(e.message));
  useLoad(load, [eventId]);

  const ack = async () => {
    setBusy(true);
    try { await api.acknowledgeEvent(eventId, ''); await load(); onChanged?.(); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };

  const checkReputation = async (indicator: string) => {
    setIntel((m) => ({ ...m, [indicator]: 'Checking…' }));
    try { const r = await api.threatIntel(indicator); setIntel((m) => ({ ...m, [indicator]: r })); }
    catch (e: any) { setIntel((m) => ({ ...m, [indicator]: e.message })); }
  };

  const ev = d?.event;
  const indicators = ev ? Array.from(new Set([ev.source_ip, ev.dest_ip, ev.domain].filter((v): v is string => !!v))) : [];
  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 flex items-start justify-center overflow-y-auto p-4" role="dialog" aria-modal="true" aria-label="Alert investigation">
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-3xl border border-slate-200 dark:border-slate-800 my-8">
        <div className="flex items-start justify-between gap-3 p-5 border-b border-slate-100 dark:border-slate-800">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-base font-bold text-slate-900 dark:text-white">{ev?.threat_category ?? 'Loading…'}</h2>
              {ev && <span className={`text-xs font-bold ${sev[ev.severity]}`}>{ev.severity} · risk {ev.risk_score}</span>}
              {ev?.is_simulated && <SimulatedBadge />}
            </div>
            <p className="font-mono text-[11px] text-slate-500">{eventId}</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>

        {error && <div role="alert" className="m-5 p-3 rounded-lg bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300 text-xs">{error}</div>}

        {ev && d && (
          <div className="p-5 space-y-5 text-xs">
            <section>
              <h3 className="font-bold text-slate-900 dark:text-white mb-1.5">What was detected</h3>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{ev.evidence}</p>
              <dl className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
                {([['Source', ev.event_source], ['Time', when(ev.timestamp)], ['Source IP', ev.source_ip], ['Destination IP', ev.dest_ip],
                  ['User', ev.user_account], ['Domain', ev.domain]] as [string, string | null | undefined][]).filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}><dt className="text-slate-400">{k}</dt><dd className="font-mono text-slate-800 dark:text-slate-200 break-all">{v}</dd></div>
                ))}
              </dl>
              <p className="mt-3 text-slate-600 dark:text-slate-400"><b>Recommended:</b> {ev.recommended_action}</p>
            </section>

            {indicators.length > 0 && (
              <section>
                <h3 className="font-bold text-slate-900 dark:text-white mb-1.5">Reputation</h3>
                <ul className="space-y-2">
                  {indicators.map((ind) => {
                    const r = intel[ind];
                    return (
                      <li key={ind} className="flex flex-wrap items-start gap-2">
                        <span className="font-mono text-slate-800 dark:text-slate-200 break-all">{ind}</span>
                        <button onClick={() => void checkReputation(ind)} className="text-sky-600 dark:text-sky-400 font-semibold hover:underline">Check reputation</button>
                        {typeof r === 'string' && <span className="text-slate-500 basis-full">{r}</span>}
                        {r && typeof r !== 'string' && (
                          <div className="basis-full text-slate-600 dark:text-slate-400">
                            {r.note && <p>{r.note}</p>}
                            {r.results.length === 0 && !r.note && <p>No reputation service applies to this indicator.</p>}
                            {r.results.map((x) => (
                              <p key={x.provider}>
                                <b className={x.verdict === 'malicious' ? 'text-red-600 dark:text-red-400' : x.verdict === 'suspicious' ? 'text-amber-600 dark:text-amber-400' : ''}>
                                  {x.provider === 'virustotal' ? 'VirusTotal' : x.provider === 'abuseipdb' ? 'AbuseIPDB' : x.provider}:
                                </b> {x.summary ?? x.status}
                              </p>
                            ))}
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </section>
            )}

            <section>
              <h3 className="font-bold text-slate-900 dark:text-white mb-1.5">How automation handled it</h3>
              {d.automation.length === 0 && <p className="text-slate-500">Not triaged yet.</p>}
              {d.automation.map((a, i) => (
                <p key={i} className="text-slate-700 dark:text-slate-300">
                  <b>Level {a.tier.slice(1)}:</b> {a.decision.replace('_', ' ')}. {a.reason}
                  {a.confidence != null && <span className="text-slate-400"> ({Math.round(a.confidence * 100)}% confidence)</span>}
                </p>
              ))}
            </section>

            <section>
              <h3 className="font-bold text-slate-900 dark:text-white mb-1.5">Attack timeline ({d.timeline.length})</h3>
              <ol className="space-y-1.5 border-l-2 border-slate-200 dark:border-slate-700 pl-4">
                {d.timeline.map((t) => (
                  <li key={t.event_id} className={t.this ? 'font-semibold' : ''}>
                    <span className="font-mono text-slate-400 mr-2">{when(t.time)}</span>
                    <span className={sev[t.severity]}>{t.severity}</span>{' '}
                    <span className="text-slate-800 dark:text-slate-200">{t.category}</span>
                    <span className="text-slate-400"> · {t.source}</span>{t.this && <span className="ml-1 text-sky-600 dark:text-sky-400">← this alert</span>}
                  </li>
                ))}
              </ol>
            </section>

            <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              <button disabled={busy || ev.is_acknowledged} onClick={() => void ack()}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg font-semibold disabled:opacity-50">
                <Check className="w-3.5 h-3.5" /> {ev.is_acknowledged ? 'Acknowledged' : 'Acknowledge alert'}
              </button>
              {ev.incident_id && onOpenIncident && (
                <button onClick={() => onOpenIncident(ev.incident_id!)} className="flex items-center gap-1 text-sky-600 dark:text-sky-400 font-semibold hover:underline">
                  Open incident {ev.incident_id} <ExternalLink className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
