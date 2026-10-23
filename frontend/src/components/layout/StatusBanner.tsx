import React, { useState } from 'react';
import { Info, Database, ShieldAlert, Cpu, ChevronRight, X } from 'lucide-react';

interface Props {
  dbMode?: string;
  reputationStatus?: string;
  onOpenSystemStatus: () => void;
}

export const StatusBanner: React.FC<Props> = ({
  dbMode = 'Local SQLite Cache',
  reputationStatus = 'Heuristic Mode',
  onOpenSystemStatus,
}) => {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  const isSupabase = dbMode.toLowerCase().includes('supabase') || dbMode.toLowerCase().includes('postgres');

  return (
    <div className="bg-slate-900 text-slate-200 border-b border-slate-800 px-4 py-2 text-xs flex flex-wrap items-center justify-between gap-3 shadow-inner">
      <div className="flex items-center flex-wrap gap-4">
        {/* SOC Notice Pill */}
        <div className="flex items-center gap-1.5 font-semibold text-sky-400 bg-sky-950/80 px-2 py-0.5 rounded border border-sky-800/60">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>SOC ENVIRONMENT NOTICE</span>
        </div>

        {/* Database Status Indicator */}
        <div className="flex items-center gap-1.5 text-slate-300">
          <Database className="w-3.5 h-3.5 text-slate-400" />
          <span>Database:</span>
          <span
            className={`font-medium px-1.5 py-0.5 rounded text-[11px] ${
              isSupabase
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'bg-amber-950 text-amber-300 border border-amber-800'
            }`}
          >
            {dbMode}
          </span>
        </div>

        {/* Intelligence / Heuristics Status */}
        <div className="hidden md:flex items-center gap-1.5 text-slate-300">
          <Cpu className="w-3.5 h-3.5 text-slate-400" />
          <span>Intelligence Engine:</span>
          <span className="text-slate-300 font-medium">Scikit-Learn NLP + Offline Rules</span>
          <span className="text-slate-500 text-[11px]">({reputationStatus})</span>
        </div>

        {/* Safe Mode Disclosure */}
        <div className="hidden lg:flex items-center gap-1 text-slate-400">
          <span>Response Actions:</span>
          <span className="text-sky-300">Simulated Safe Containment</span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={onOpenSystemStatus}
          className="flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium underline-offset-2 hover:underline transition"
        >
          <span>View Integrations & Audit Config</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => setDismissed(true)}
          className="text-slate-400 hover:text-slate-200 p-1 hover:bg-slate-800 rounded transition"
          title="Minimize banner"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
