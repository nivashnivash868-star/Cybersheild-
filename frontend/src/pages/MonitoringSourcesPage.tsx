import React, { useState, useEffect } from 'react';
import {
  Activity, ShieldCheck, Server, AlertTriangle, RefreshCw,
  Radio, CheckCircle2, Wifi, Zap, Clock, Terminal, Globe,
  ShieldAlert, Mail, Laptop, HardDrive, KeyRound, Cloud
} from 'lucide-react';
import { api } from '../api/client';
import { MonitoringSource, SecurityEvent } from '../types';

export const MonitoringSourcesPage: React.FC = () => {
  const [sources, setSources] = useState<MonitoringSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [pulsing, setPulsing] = useState(false);
  const [pulseResult, setPulseResult] = useState<{ pulse_events_generated: number; new_events: SecurityEvent[] } | null>(null);
  const [lastCheckTime, setLastCheckTime] = useState<string>('');

  const loadSources = async () => {
    setLoading(true);
    try {
      const data = await api.getMonitoringSources();
      setSources(data);
      setLastCheckTime(new Date().toTimeString().split(' ')[0] + ' UTC');
    } catch (err) {
      console.error('Failed to load monitoring sources:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSources();
    const interval = setInterval(loadSources, 20000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulatePulse = async () => {
    setPulsing(true);
    setPulseResult(null);
    try {
      const res = await api.simulateMonitoringPulse();
      setPulseResult(res);
      await loadSources();
    } catch (err: any) {
      alert(`Pulse failed: ${err.message}`);
    } finally {
      setPulsing(false);
    }
  };

  const getSourceIcon = (sourceType: string) => {
    switch (sourceType.toUpperCase()) {
      case 'EMAIL_SECURITY':
        return <Mail className="w-5 h-5 text-sky-500" />;
      case 'EDR_ENDPOINT':
        return <Laptop className="w-5 h-5 text-indigo-500" />;
      case 'DNS_SECURITY':
        return <Globe className="w-5 h-5 text-teal-500" />;
      case 'FIREWALL':
        return <ShieldCheck className="w-5 h-5 text-amber-500" />;
      case 'ZEEK_NETWORK':
        return <Activity className="w-5 h-5 text-purple-500" />;
      case 'IDENTITY_PROVIDER':
        return <KeyRound className="w-5 h-5 text-emerald-500" />;
      case 'CLOUD_AUDIT':
        return <Cloud className="w-5 h-5 text-blue-500" />;
      default:
        return <Server className="w-5 h-5 text-slate-500" />;
    }
  };

  const totalEventsIngested = sources.reduce((sum, s) => sum + (s.event_count || 0), 0);
  const activeSources = sources.filter((s) => s.status === 'ONLINE').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white p-6 rounded-xl border border-slate-200 shadow-xs">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-sky-50 text-sky-600 flex items-center justify-center border border-sky-200">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                24/7 Continuous Telemetry & Monitoring Engine
              </h1>
              <p className="text-xs text-slate-500">
                Multi-source security telemetry ingestion across corporate email, endpoints, DNS, firewall, identity, and cloud audit logs.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadSources}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition"
            title="Refresh Heartbeat"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Poll Health</span>
          </button>

          <button
            onClick={handleSimulatePulse}
            disabled={pulsing}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-700 text-white rounded-lg transition shadow-xs disabled:opacity-50"
          >
            <Zap className={`w-4 h-4 ${pulsing ? 'animate-bounce text-amber-300' : 'text-amber-300'}`} />
            <span>{pulsing ? 'Injecting Telemetry Pulse...' : 'Simulate 24/7 Telemetry Pulse'}</span>
          </button>
        </div>
      </div>

      {/* KPI Counters */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
            <span>Ingestion Pipelines</span>
            <Server className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold text-slate-900">{sources.length} Configured</div>
          <p className="text-[11px] text-slate-400 mt-0.5">Corporate authorized sensors</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
            <span>Online Sensors</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold text-emerald-600">
            {activeSources} / {sources.length} Active
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">Continuous pulse verification</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
            <span>Events Processed</span>
            <Activity className="w-4 h-4 text-sky-500" />
          </div>
          <div className="text-2xl font-bold text-sky-600">{totalEventsIngested.toLocaleString()}</div>
          <p className="text-[11px] text-slate-400 mt-0.5">Cumulative pipeline throughput</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
            <span>Last Heartbeat Check</span>
            <Clock className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-base font-mono font-bold text-slate-800">{lastCheckTime || 'Syncing...'}</div>
          <p className="text-[11px] text-slate-400 mt-0.5">Every 20 seconds automated sync</p>
        </div>
      </div>

      {/* Pulse Injection Toast */}
      {pulseResult && (
        <div className="p-4 rounded-xl bg-sky-50 border border-sky-200 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-sky-600 text-white flex items-center justify-center">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <p className="font-bold text-sky-900">
                Telemetry Pulse Successfully Dispatched ({pulseResult.pulse_events_generated} security events generated)
              </p>
              <p className="text-sky-700">
                Ingested through real-time ML anomaly & threat detection engine. Incidents updated automatically.
              </p>
            </div>
          </div>
          <button
            onClick={() => setPulseResult(null)}
            className="text-xs font-semibold text-sky-800 hover:text-sky-900 underline self-start md:self-auto"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Disclosure Card: Simulated Mode Guarantee */}
      <div className="bg-amber-50/70 border border-amber-200 p-4 rounded-xl text-xs text-amber-900 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold">Transparent Telemetry Source Disclosure:</span>
          <p className="mt-0.5 text-amber-800 leading-relaxed">
            All 7 ingestion pipelines below are currently operating in{' '}
            <span className="font-semibold underline">Calibrated Security Simulation Mode</span>. Unless production API keys 
            (e.g., AWS CloudTrail ARN, CrowdStrike OAuth Client Secret, Cisco Umbrella API Key) are configured in the environment,
            events are generated by the CYBERSHIELD telemetry synthesizer to replicate real corporate attack patterns without faking live third-party connectivity.
          </p>
        </div>
      </div>

      {/* Monitoring Source Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading && sources.length === 0 ? (
          <div className="col-span-full py-12 text-center text-slate-500">
            <div className="w-6 h-6 border-2 border-sky-600 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
            <span>Discovering telemetry ingestion sources...</span>
          </div>
        ) : (
          sources.map((src) => (
            <div
              key={src.source_id}
              className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs hover:border-slate-300 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-slate-50 border border-slate-200">
                      {getSourceIcon(src.source_type)}
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-slate-900">{src.name}</h3>
                      <p className="text-[11px] font-mono text-slate-400">{src.source_id}</p>
                    </div>
                  </div>

                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    {src.status}
                  </span>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed mb-4">
                  {src.description}
                </p>
              </div>

              <div className="space-y-2 pt-3 border-t border-slate-100 text-[11px]">
                <div className="flex items-center justify-between text-slate-500">
                  <span>Throughput:</span>
                  <span className="font-semibold text-slate-800 font-mono">
                    {src.event_count} events
                  </span>
                </div>

                <div className="flex items-center justify-between text-slate-500">
                  <span>Last Heartbeat:</span>
                  <span className="font-mono text-slate-600">
                    {new Date(src.last_heartbeat).toLocaleTimeString()}
                  </span>
                </div>

                <div className="flex items-center justify-between text-slate-500">
                  <span>Integration Status:</span>
                  <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-medium">
                    {src.is_simulated ? 'Calibrated Simulation' : 'Live Connected'}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
