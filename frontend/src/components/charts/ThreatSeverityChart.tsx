import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { ThreatSeverityDistribution } from '../../types';

interface Props {
  data: ThreatSeverityDistribution;
}

export const ThreatSeverityChart: React.FC<Props> = ({ data }) => {
  const chartData = [
    { name: 'Critical', value: data.critical, color: '#ef4444' },
    { name: 'High', value: data.high, color: '#f97316' },
    { name: 'Medium', value: data.medium, color: '#f59e0b' },
    { name: 'Low / Info', value: data.low, color: '#10b981' },
  ].filter((item) => item.value > 0);

  const total = (data.critical + data.high + data.medium + data.low) || 1;

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs flex flex-col h-full">
      <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-2">
        <div>
          <h4 className="text-sm font-semibold text-slate-900">Threat Severity Distribution</h4>
          <p className="text-xs text-slate-500">Classification across active telemetry</p>
        </div>
        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
          {total} Total
        </span>
      </div>

      <div className="h-56 relative flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              innerRadius={55}
              outerRadius={80}
              paddingAngle={3}
              dataKey="value"
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="#ffffff" strokeWidth={2} />
              ))}
            </Pie>
            <Tooltip
              formatter={(val: any, name: any) => [`${val} (${Math.round((Number(val) / total) * 100)}%)`, name]}
              contentStyle={{
                backgroundColor: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                fontSize: '12px',
                boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute text-center pointer-events-none">
          <div className="text-xl font-bold text-slate-800">{data.critical + data.high}</div>
          <div className="text-[10px] uppercase font-semibold text-red-600 tracking-wider">Elevated</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-100 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
          <span className="text-slate-600">Critical:</span>
          <span className="font-semibold text-slate-900 ml-auto">{data.critical}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
          <span className="text-slate-600">High:</span>
          <span className="font-semibold text-slate-900 ml-auto">{data.high}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
          <span className="text-slate-600">Medium:</span>
          <span className="font-semibold text-slate-900 ml-auto">{data.medium}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
          <span className="text-slate-600">Low:</span>
          <span className="font-semibold text-slate-900 ml-auto">{data.low}</span>
        </div>
      </div>
    </div>
  );
};
