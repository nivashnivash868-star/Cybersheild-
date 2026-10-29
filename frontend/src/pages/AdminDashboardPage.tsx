import React, { useCallback, useState } from 'react';
import { RefreshCw, ShieldAlert, Users, AlertTriangle, ClipboardCheck, Activity, UserPlus, SlidersHorizontal, ScrollText } from 'lucide-react';
import { api } from '../api/client';
import { AdminOverview } from '../types';
import { SimulatedBanner } from '../components/common/Simulated';
import { useLoad } from '../hooks/useLoad';

interface Props {
  onNavigateToTab: (tab: any) => void;
}

const dot: Record<string, string> = { ok: 'bg-emerald-500', warn: 'bg-amber-500', down: 'bg-red-500' };
const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800';

const Kpi: React.FC<{ label: string; value: number | string; sub?: string; icon: React.ReactNode; tint: string; danger?: boolean }> = ({ label, value, sub, icon, tint, danger }) => (
  <div className={card + ' p-4'}>
    <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1"><span className="font-medium text-[11px]">{label}</span><div className={`w-6 h-6 rounded flex items-center justify-center ${tint}`}>{icon}</div></div>
    <div className={`text-2xl font-bold ${danger ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-white'}`}>{value}</div>
    {sub && <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">{sub}</div>}
  </div>
);

export const AdminDashboardPage: React.FC<Props> = ({ onNavigateToTab }) => {
  const [o, setO] = useState<AdminOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setO(await api.getAdminOverview()); setError(null); } catch (e: any) { setError(e.message); }
  }, []);
  useLoad(load, [load], { every: 15000 });

  const attention: { text: string; tab: string; tone: string }[] = [];
  if (o) {
    if (o.incidents.awaiting_admin > 0) attention.push({ text: `${o.incidents.awaiting_admin} high-impact decision(s) need your approval (disable accounts, isolate hosts, close Critical incidents, alert rules)`, tab: 'soc_ops', tone: 'text-amber-700 dark:text-amber-300' });
    if (o.alerts.unacknowledged_high > 0) attention.push({ text: `${o.alerts.unacknowledged_high} High or Critical alert(s) are not acknowledged yet`, tab: 'overview', tone: 'text-red-700 dark:text-red-300' });
    if (o.analysts.without_mfa > 0) attention.push({ text: `${o.analysts.without_mfa} active analyst(s) have not enabled MFA`, tab: 'administration', tone: 'text-amber-700 dark:text-amber-300' });
    if (o.analysts.never_signed_in > 0) attention.push({ text: `${o.analysts.never_signed_in} analyst account(s) have never signed in (invite pending)`, tab: 'administration', tone: 'text-slate-600 dark:text-slate-300' });
    o.health.filter((h) => h.status !== 'ok').forEach((h) => attention.push({ text: `${h.name}: ${h.detail}`, tab: 'administration', tone: h.status === 'down' ? 'text-red-700 dark:text-red-300' : 'text-slate-600 dark:text-slate-300' }));
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Security Administrator</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Accounts, approvals, configuration and the health of the platform</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => onNavigateToTab('administration')} className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold"><UserPlus className="w-3.5 h-3.5" /> Create analyst</button>
          <button onClick={() => void load()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
        </div>
      </div>

      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>}
      {o && <SimulatedBanner simulated={o.data.simulated_events} total={o.data.total_events} />}

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5">
        <Kpi label="Total alerts" value={o ? o.alerts.total.toLocaleString() : '-'} sub={o ? `${o.alerts.last_24h.toLocaleString()} in the last 24h` : undefined} icon={<Activity className="w-3.5 h-3.5" />} tint="bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-400" />
        <Kpi label="Critical incidents" value={o?.incidents.critical ?? '-'} sub="open" icon={<ShieldAlert className="w-3.5 h-3.5" />} tint="bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400" danger={(o?.incidents.critical ?? 0) > 0} />
        <Kpi label="Unresolved threats" value={o?.incidents.unresolved ?? '-'} sub="incidents not yet closed" icon={<AlertTriangle className="w-3.5 h-3.5" />} tint="bg-amber-50 dark:bg-amber-950 text-amber-600 dark:text-amber-400" />
        <Kpi label="Active analysts" value={o?.analysts.active ?? '-'} sub={o ? `${o.analysts.online_now} online now` : undefined} icon={<Users className="w-3.5 h-3.5" />} tint="bg-sky-50 dark:bg-sky-950 text-sky-600 dark:text-sky-400" />
        <Kpi label="Awaiting approval" value={o?.incidents.awaiting_approval ?? '-'} sub={o ? `${o.incidents.awaiting_admin} need an administrator` : undefined} icon={<ClipboardCheck className="w-3.5 h-3.5" />} tint="bg-violet-50 dark:bg-violet-950 text-violet-600 dark:text-violet-400" danger={(o?.incidents.awaiting_admin ?? 0) > 0} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className={card + ' p-4 space-y-3'}>
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Needs your attention</h2>
          {o && attention.length === 0 && <p className="text-xs text-emerald-600 dark:text-emerald-400">Nothing needs attention.</p>}
          <ul className="space-y-2">
            {attention.map((a, i) => (
              <li key={i} className="text-xs flex items-start justify-between gap-3">
                <span className={a.tone}>{a.text}</span>
                <button onClick={() => onNavigateToTab(a.tab)} className="font-semibold text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap">Open →</button>
              </li>
            ))}
          </ul>
        </section>

        <section className={card + ' p-4 space-y-3'}>
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">System health</h2>
          <ul className="space-y-2">
            {o?.health.map((h) => (
              <li key={h.name} className="text-xs flex items-center gap-3">
                <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${dot[h.status]}`} aria-label={h.status} />
                <span className="font-semibold text-slate-900 dark:text-white w-44 shrink-0">{h.name}</span>
                <span className="text-slate-500 dark:text-slate-400">{h.detail}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        {[
          { tab: 'administration', icon: <Users className="w-4 h-4" />, title: 'Accounts and access', text: 'Create analysts, deactivate accounts, reset MFA' },
          { tab: 'administration', icon: <SlidersHorizontal className="w-4 h-4" />, title: 'Security configuration', text: 'Severity thresholds, alerting, integrations, role permissions' },
          { tab: 'administration', icon: <ScrollText className="w-4 h-4" />, title: 'Audit log', text: `${o?.audit_entries.toLocaleString() ?? '…'} recorded actions; verify integrity` },
        ].map((q) => (
          <button key={q.title} onClick={() => onNavigateToTab(q.tab)} className={card + ' p-4 text-left hover:border-sky-400 transition'}>
            <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white">{q.icon}{q.title}</div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{q.text}</p>
          </button>
        ))}
      </div>
    </div>
  );
};
