import React, { useState, useEffect } from 'react';
import {
  Network, Activity, AlertOctagon, CheckCircle2, ShieldCheck,
  Send, Sparkles, Server, Terminal, Filter, ShieldAlert
} from 'lucide-react';
import { api } from '../api/client';
import { NetworkAnalysisBatchResult } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const NetworkAnomalyPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('brute_force_ssh');
  const [rawRecordsJson, setRawRecordsJson] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<NetworkAnalysisBatchResult | null>(null);

  useEffect(() => {
    api.getNetworkSamples().then((data) => {
      setScenarios(data);
      if (data.length > 0) {
        setSelectedScenarioId(data[0].id);
        setRawRecordsJson(JSON.stringify(data[0].records, null, 2));
      }
    }).catch(console.error);
  }, []);

  const handleSelectScenario = (id: string) => {
    setSelectedScenarioId(id);
    const scen = scenarios.find((s) => s.id === id);
    if (scen) {
      setRawRecordsJson(JSON.stringify(scen.records, null, 2));
      setError(null);
    }
  };

  const handleRunAnalysis = async () => {
    setError(null);
    let parsedRecords: any[] = [];
    try {
      parsedRecords = JSON.parse(rawRecordsJson);
      if (!Array.isArray(parsedRecords)) {
        throw new Error('Input must be a JSON array of network log records.');
      }
    } catch (e: any) {
      setError(`Invalid JSON syntax: ${e.message}`);
      return;
    }

    setLoading(true);
    try {
      const res = await api.analyzeNetworkBatch(parsedRecords);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Network anomaly detection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-200">
        <h1 className="text-xl font-bold tracking-tight text-slate-900">Network Anomaly & Traffic Flow Detection</h1>
        <p className="text-xs text-slate-500">
          Stateful connection tracking, port dispersion heuristics, and Scikit-Learn Isolation Forest outlier scoring
        </p>
      </div>

      {/* Preset Scenarios Selector */}
      <div className="bg-sky-50 border border-sky-200 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles className="w-4 h-4 text-sky-700" />
          <h3 className="text-xs font-semibold text-sky-900 uppercase tracking-wider">
            Curated Labeled Synthetic Log Scenarios
          </h3>
        </div>
        <p className="text-xs text-sky-800 mb-3">
          Select imported telemetry datasets to evaluate heuristic rules and multivariate machine learning models:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {scenarios.map((s) => (
            <button
              key={s.id}
              onClick={() => handleSelectScenario(s.id)}
              className={`text-left p-2.5 rounded-md border text-xs transition ${
                selectedScenarioId === s.id
                  ? 'bg-sky-600 text-white border-sky-600 shadow-xs'
                  : 'bg-white border-sky-200 text-slate-800 hover:border-sky-400'
              }`}
            >
              <div className="font-semibold text-[11px] truncate">{s.name}</div>
              <p
                className={`text-[10px] mt-1 line-clamp-2 ${
                  selectedScenarioId === s.id ? 'text-sky-100' : 'text-slate-500'
                }`}
              >
                {s.description}
              </p>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Raw Records Editor */}
        <div className="lg:col-span-5 bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-slate-600" />
              <span>Structured Network Flow Logs</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
              JSON Format
            </span>
          </div>

          <div>
            <textarea
              rows={14}
              value={rawRecordsJson}
              onChange={(e) => setRawRecordsJson(e.target.value)}
              className="w-full p-3 font-mono text-[11px] rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500 bg-slate-900 text-slate-100"
            />
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-[11px] text-slate-600 space-y-1">
            <p className="font-semibold text-slate-800">Operational Integrity Note:</p>
            <p>
              Operating on imported/synthetic flow records. Real-time inline packet capture requires physical TAP or configured Zeek sensor daemon.
            </p>
          </div>

          {error && (
            <div className="p-3 bg-red-50 text-red-800 border border-red-200 rounded-lg text-xs">
              {error}
            </div>
          )}

          <button
            onClick={handleRunAnalysis}
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-sky-600 text-white font-medium text-xs hover:bg-sky-700 transition flex items-center justify-center gap-2 shadow-xs disabled:opacity-50"
          >
            {loading ? (
              <span>Executing Rules & Isolation Forest...</span>
            ) : (
              <>
                <Send className="w-3.5 h-3.5" />
                <span>Analyze Ingested Traffic Records</span>
              </>
            )}
          </button>
        </div>

        {/* Right: Detected Anomalies */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-5">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-3 p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">Total Flows</span>
                  <span className="text-xl font-bold text-slate-900">{result.total_records_analyzed}</span>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-bold text-red-600 block">Anomalies Detected</span>
                  <span className="text-xl font-bold text-red-600">{result.anomalies_detected}</span>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-bold text-emerald-600 block">Nominal / Benign</span>
                  <span className="text-xl font-bold text-emerald-700">{result.benign_count}</span>
                </div>
              </div>

              {/* Engine Used Footnote */}
              <p className="text-[11px] text-slate-500 font-mono">
                Engine: {result.engine_used}
              </p>

              {/* Alerts List */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                  Flagged Threat Detections ({result.alerts.length})
                </h4>

                {result.alerts.length === 0 ? (
                  <div className="p-4 rounded-lg bg-emerald-50 text-emerald-900 border border-emerald-200 text-xs text-center">
                    All ingested network flows conformed to nominal multivariate traffic distributions.
                  </div>
                ) : (
                  result.alerts.map((alert) => (
                    <div
                      key={alert.event_id}
                      className="p-4 rounded-lg border border-slate-200 bg-white hover:border-slate-300 transition space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={alert.severity} size="sm" />
                          <span className="font-bold text-slate-900">{alert.event_type}</span>
                        </div>
                        <span className="text-[11px] font-bold text-slate-800">
                          Risk: {alert.risk_score}/100
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-50 p-2 rounded border border-slate-100">
                        <div>
                          <span className="text-slate-400 block font-sans text-[9px] uppercase">Source Endpoint</span>
                          <span className="font-medium text-slate-900">{alert.source_ip}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-sans text-[9px] uppercase">Destination</span>
                          <span className="font-medium text-slate-900">
                            {alert.destination_ip}:{alert.destination_port} ({alert.protocol})
                          </span>
                        </div>
                      </div>

                      <p className="text-slate-700 text-xs">{alert.detection_reason}</p>

                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {alert.evidence_tokens.map((tok, i) => (
                          <span
                            key={i}
                            className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200"
                          >
                            {tok}
                          </span>
                        ))}
                      </div>

                      <div className="p-2.5 rounded bg-sky-50 text-sky-950 border border-sky-100 flex items-start gap-1.5 text-xs">
                        <CheckCircle2 className="w-3.5 h-3.5 text-sky-600 mt-0.5 shrink-0" />
                        <span>
                          <strong>Recommended Response:</strong> {alert.recommended_response}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="h-full min-h-[420px] bg-slate-50 rounded-lg border border-dashed border-slate-300 p-8 flex flex-col items-center justify-center text-center">
              <div className="w-12 h-12 rounded-full bg-slate-200 flex items-center justify-center text-slate-500 mb-3">
                <Network className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-semibold text-slate-700">Awaiting Log Ingestion</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select an attack scenario from the top panel or paste custom NetFlow JSON records to run detection.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
