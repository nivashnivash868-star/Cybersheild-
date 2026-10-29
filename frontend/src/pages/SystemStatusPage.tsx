import React, { useState } from 'react';
import {
  Database, Cpu, CheckCircle2, RefreshCw, Lock, Activity
} from 'lucide-react';
import { api } from '../api/client';
import { SystemStatusData } from '../types';
import { useLoad } from '../hooks/useLoad';

export const SystemStatusPage: React.FC = () => {
  const [statusData, setStatusData] = useState<SystemStatusData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadStatus = async () => {
    setLoading(true);
    try {
      const data = await api.getSystemStatus();
      setStatusData(data);
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useLoad(loadStatus, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">System Diagnostics & Environment Integrity</h1>
          <p className="text-xs text-slate-500">
            Real-time status of database backends, threat intelligence feeds, machine learning engines, and SSRF guardrails
          </p>
        </div>

        <button
          onClick={loadStatus}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-slate-700 text-xs font-medium hover:bg-slate-50 transition shadow-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Diagnostics</span>
        </button>
      </div>

      {statusData ? (
        <div className="space-y-6">
          {/* Database Infrastructure Status */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Database className="w-4 h-4 text-sky-600" />
                <span>Primary Relational Database Engine</span>
              </h3>
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-semibold ${
                  statusData.database.is_demo_mode
                    ? 'bg-amber-100 text-amber-800 border border-amber-200'
                    : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                }`}
              >
                {statusData.database.provider}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-slate-500 font-semibold text-[10px] uppercase">Engine Mode</span>
                <p className="font-bold text-slate-900">
                  {statusData.database.is_demo_mode ? 'Local SQLite SOC Cache (Demo Mode)' : 'Supabase PostgreSQL'}
                </p>
                <p className="text-slate-600 text-[11px]">{statusData.database.notice}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-slate-500 font-semibold text-[10px] uppercase">Connection Target</span>
                <p className="font-mono text-slate-900 font-semibold">{statusData.database.target}</p>
                <p className="text-slate-500 text-[11px]">
                  To connect to Supabase PostgreSQL, add SUPABASE_DATABASE_URL to backend/.env.
                </p>
              </div>
            </div>
          </div>

          {/* External Integrations */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs space-y-4">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 pb-2 border-b border-slate-100">
              <Activity className="w-4 h-4 text-sky-600" />
              <span>External Threat Intelligence & Response Integrations</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {Object.entries(statusData.integrations).map(([key, val]) => (
                <div key={key} className="p-3.5 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900 uppercase text-[11px]">
                      {key.replace(/_/g, ' ')}
                    </span>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                        val.configured
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {val.status}
                    </span>
                  </div>
                  <p className="text-slate-600 text-[11px]">{val.details}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Machine Learning & AI Engines */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs space-y-4">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 pb-2 border-b border-slate-100">
              <Cpu className="w-4 h-4 text-sky-600" />
              <span>Machine Learning & Heuristic Classification Models</span>
            </h3>

            <div className="space-y-2 text-xs">
              {Object.entries(statusData.ml_engine).map(([k, v]) => (
                <div
                  key={k}
                  className="p-3 rounded-lg border border-slate-200 bg-slate-50 flex flex-col sm:flex-row sm:items-center justify-between gap-1"
                >
                  <span className="font-semibold text-slate-800 uppercase text-[11px]">
                    {k.replace(/_/g, ' ')}:
                  </span>
                  <span className="font-mono text-sky-800 font-medium text-[11px]">{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Security & SSRF Guardrails */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-xs space-y-4">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 pb-2 border-b border-slate-100">
              <Lock className="w-4 h-4 text-sky-600" />
              <span>Active Security Enforcements & Defensive Guardrails</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              {Object.entries(statusData.security_guards).map(([k, v]) => (
                <div key={k} className="p-3 rounded-lg bg-emerald-50/60 border border-emerald-200 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-emerald-900 text-[11px] uppercase">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    <span>{k.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="text-emerald-800 text-[11px]">{v}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-xs text-slate-400">Loading system status...</div>
      )}
    </div>
  );
};
