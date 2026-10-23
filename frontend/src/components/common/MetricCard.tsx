import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: {
    text: string;
    isPositive?: boolean;
    isNegative?: boolean;
  };
  variant?: 'default' | 'danger' | 'warning' | 'info';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'default',
}) => {
  let borderLeft = 'border-l-sky-600';
  if (variant === 'danger') borderLeft = 'border-l-red-500';
  if (variant === 'warning') borderLeft = 'border-l-amber-500';
  if (variant === 'info') borderLeft = 'border-l-sky-500';

  return (
    <div className={`bg-white rounded-lg border border-slate-200 border-l-4 ${borderLeft} p-5 shadow-xs transition hover:shadow-sm`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{title}</p>
          <h3 className="mt-2 text-2xl font-bold tracking-tight text-slate-900">{value}</h3>
        </div>
        <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100 text-sky-700">
          {icon}
        </div>
      </div>
      {(subtitle || trend) && (
        <div className="mt-3 flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-100">
          {subtitle && <span>{subtitle}</span>}
          {trend && (
            <span
              className={`font-medium ${
                trend.isNegative
                  ? 'text-red-600'
                  : trend.isPositive
                  ? 'text-emerald-600'
                  : 'text-slate-600'
              }`}
            >
              {trend.text}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
