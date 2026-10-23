import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, GitMerge, Search, Filter, RefreshCw, CheckCircle2,
  AlertTriangle, ArrowRight, Layers, HelpCircle
} from 'lucide-react';
import { api } from '../api/client';
import { SecurityEvent } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface Props {
  onSelectIncident: (id: string) => void;
}

export const UnifiedRiskPage: React.FC<Props> = ({ onSelectIncident }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);
  const [correlationFeedback, setCorrelationFeedback] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('All');
  const [sourceFilter, setSourceFilter] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');

  const loadEvents = async () => {
    setLoading(true);
    try {
      const data = await api.getEvents({
        severity: severityFilter,
        source: sourceFilter,
        search: searchQuery,
        limit: 100,
      });
      setEvents(data);
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [severityFilter, sourceFilter]);

  const handleCorrelationRun = async () => {
    setCorrelating(true);
    setCorrelationFeedback(null);
    try {
      const res = await api.runCorrelationCycle();
      if (res.correlations_created > 0) {
        setCorrelationFeedback(
          `Success: Formed ${res.correlations_created} correlated incident(s) across multi-sensor pivot clusters.`
        );
      } else {
        setCorrelationFeedback('Correlation Cycle Completed: No new unlinked clusters met correlation thresholds.');
      }
      loadEvents();
    } catch (err: any) {
      setCorrelationFeedback(`Correlation failed: ${err.message}`);
    } finally {
      setCorrelating(false);
    }
  };

  const correlatedEvents = events.filter((e) => e.incident_id);
  const uncorrelatedEvents = events.filter((e) => !e.incident_id);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">
            Unified Risk Assessment & Event Correlation
          </h1>
          <p className="text-xs text-slate-500">
            Centralized multi-source scoring rules, shared pivot matching, and suspected incident synthesis
          </p>
        </div>

        <button
          onClick={handleCorrelationRun}
          disabled={correlating}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-sky-600 text-white text-xs font-medium hover:bg-sky-700 transition shadow-xs disabled:opacity-50"
        >
          <GitMerge className={`w-3.5 h-3.5 ${correlating ? 'animate-spin' : ''}`} />
          <span>{correlating ? 'Correlating Sensor Streams...' : 'Execute Correlation Cycle'}</span>
        </button>
      </div>

      {correlationFeedback && (
        <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 text-sky-900 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-sky-600" />
            <span>{correlationFeedback}</span>
          </div>
          <button onClick={() => setCorrelationFeedback(null)} className="font-semibold text-slate-500 hover:text-slate-700">
            Dismiss
          </button>
        </div>
      )}

      {/* Correlation Logic Architecture Info */}
      <div className="p-4 rounded-lg bg-slate-900 text-slate-200 text-xs space-y-2">
        <div className="flex items-center gap-2 text-sky-400 font-semibold uppercase tracking-wider text-[11px]">
          <Layers className="w-4 h-4" />
          <span>Correlation Model Logic</span>
        </div>
        <p className="text-slate-300 leading-relaxed text-[11px]">
          Events are linked across Email Gateways, NIDS Sensors, EDR Agents, and Auth Logs using shared pivots (IP Address, Target Domain, SHA-256 Hash, or Compromised User Account) within temporal operational proximity. When cross-domain pivots align, a suspected Incident is generated with an explicit uncertainty rating.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="p-3 bg-white border border-slate-200 rounded-lg flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-1.5 font-semibold text-slate-700">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span>Filters:</span>
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1 rounded border border-slate-300 bg-white text-slate-800 focus:outline-none"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-2.5 py-1 rounded border border-slate-300 bg-white text-slate-800 focus:outline-none"
          >
            <option value="All">All Sensors</option>
            <option value="Email">Email Gateway</option>
            <option value="Endpoint">Endpoint EDR</option>
            <option value="Network">Network / Zeek</option>
            <option value="WAF">Cloudflare WAF</option>
            <option value="SSHD">SSHD Bastion</option>
          </select>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            loadEvents();
          }}
          className="relative"
        >
          <input
            type="text"
            placeholder="Search IP, domain, hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1 text-xs rounded-lg border border-slate-300 focus:outline-none w-52"
          />
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
        </form>
      </div>

      {/* Events Table */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-800">
            Ingested Security Events ({events.length} Total: {correlatedEvents.length} Correlated, {uncorrelatedEvents.length} Unlinked)
          </span>
          <button onClick={loadEvents} className="text-slate-500 hover:text-slate-800 flex items-center gap-1">
            <RefreshCw className="w-3 h-3" />
            <span>Refresh</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100/70 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Event ID</th>
                <th className="py-2.5 px-4">Sensor Source</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Risk</th>
                <th className="py-2.5 px-4">Shared Pivot Key</th>
                <th className="py-2.5 px-4">Correlation Status</th>
                <th className="py-2.5 px-4 text-right">Incident Link</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-normal">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    Loading security event matrix...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No security events found.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-slate-50 transition">
                    <td className="py-2.5 px-4 font-mono font-medium text-sky-700">{ev.event_id}</td>
                    <td className="py-2.5 px-4 text-slate-700">{ev.event_source}</td>
                    <td className="py-2.5 px-4 text-slate-900 font-medium">{ev.threat_category}</td>
                    <td className="py-2.5 px-4">
                      <SeverityBadge severity={ev.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-4 font-bold text-slate-800">{ev.risk_score}</td>
                    <td className="py-2.5 px-4 font-mono text-slate-700">
                      {ev.source_ip ? (
                        <span className="bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                          IP: {ev.source_ip}
                        </span>
                      ) : ev.domain ? (
                        <span className="bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                          Host: {ev.domain}
                        </span>
                      ) : ev.file_hash ? (
                        <span className="bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                          Hash: {ev.file_hash.slice(0, 10)}...
                        </span>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      {ev.incident_id ? (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-medium text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Correlated</span>
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[11px]">Awaiting Correlation</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {ev.incident_id ? (
                        <button
                          onClick={() => onSelectIncident(ev.incident_id!)}
                          className="px-2 py-1 rounded bg-sky-50 text-sky-700 hover:bg-sky-100 font-semibold text-[11px] transition inline-flex items-center gap-1"
                        >
                          <span>{ev.incident_id}</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      ) : (
                        <span className="text-slate-300 text-[11px]">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
