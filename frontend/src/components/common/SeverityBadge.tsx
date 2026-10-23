import React from 'react';
import { Severity } from '../../types';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const norm = (severity || 'Low').toLowerCase();

  let colorClasses = 'bg-slate-100 text-slate-700 border-slate-200';

  if (norm === 'critical') {
    colorClasses = 'bg-red-50 text-red-700 border-red-200 font-semibold';
  } else if (norm === 'high') {
    colorClasses = 'bg-orange-50 text-orange-700 border-orange-200 font-semibold';
  } else if (norm === 'medium') {
    colorClasses = 'bg-amber-50 text-amber-800 border-amber-200 font-medium';
  } else if (norm === 'low' || norm === 'benign') {
    colorClasses = 'bg-emerald-50 text-emerald-700 border-emerald-200 font-medium';
  } else if (norm === 'info') {
    colorClasses = 'bg-sky-50 text-sky-700 border-sky-200 font-medium';
  }

  const sizeClasses =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-xs'
      : size === 'lg'
      ? 'px-3 py-1 text-sm'
      : 'px-2.5 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border tracking-wide uppercase ${sizeClasses} ${colorClasses}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          norm === 'critical'
            ? 'bg-red-500 animate-pulse'
            : norm === 'high'
            ? 'bg-orange-500'
            : norm === 'medium'
            ? 'bg-amber-500'
            : 'bg-emerald-500'
        }`}
      />
      {severity}
    </span>
  );
};
