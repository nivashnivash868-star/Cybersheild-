import React from 'react';
import { FlaskConical } from 'lucide-react';

export const SimulatedBadge: React.FC<{ className?: string }> = ({ className = '' }) => (
  <span
    title="This record is simulated test data, not real telemetry."
    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-violet-300 dark:border-violet-800 bg-violet-50 dark:bg-violet-950/50 text-violet-700 dark:text-violet-300 text-[9px] font-bold tracking-wider ${className}`}
  >
    <FlaskConical className="w-2.5 h-2.5" /> SIMULATED
  </span>
);

/** Shown on dashboards whenever any stored event is fabricated, so nobody mistakes demo data for live telemetry. */
export const SimulatedBanner: React.FC<{ simulated: number; total: number }> = ({ simulated, total }) => {
  if (simulated <= 0) return null;
  const all = simulated >= total;
  return (
    <div className="p-3 rounded-lg border border-violet-300 dark:border-violet-800 bg-violet-50 dark:bg-violet-950/40 text-xs text-violet-800 dark:text-violet-200 flex items-start gap-2">
      <FlaskConical className="w-4 h-4 shrink-0 mt-0.5" />
      <span>
        <b>{all ? 'All data shown is simulated.' : `${simulated.toLocaleString()} of ${total.toLocaleString()} events are simulated.`}</b>{' '}
        Simulated events are test data, not real telemetry, and are marked SIMULATED wherever they appear.
        {all ? ' Connect a real data source to monitor live activity.' : ''}
      </span>
    </div>
  );
};
