import React, { useCallback, useState } from 'react';
import { ShieldCheck, UserPlus, RefreshCw, Search, BadgeCheck, TriangleAlert } from 'lucide-react';
import { api } from '../api/client';
import { AdminUser, AuditEntry, IntegrationRow, IntegrationTestResult, PermissionRow, SettingDef, UserRole, UserSession } from '../types';
import { useLoad } from '../hooks/useLoad';

interface Props {
  currentUser: UserSession;
}

const ROLES: UserRole[] = ['Super Admin', 'Security Administrator', 'SOC Analyst', 'Employee'];
const when = (iso: string | null) => (iso ? new Date(/[zZ]$/.test(iso) ? iso : iso + 'Z').toLocaleString() : 'never');

const field = 'px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';
const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800';

export const AdministrationPage: React.FC<Props> = ({ currentUser }) => {
  const isSuper = currentUser.role === 'Super Admin';
  const roleChoices: UserRole[] = isSuper ? ROLES : ['SOC Analyst', 'Employee'];
  const [tab, setTab] = useState<'users' | 'audit' | 'config'>('users');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // users
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [form, setForm] = useState({ email: '', full_name: '', role: 'SOC Analyst', department: '', temporary_password: '' });
  const [mode, setMode] = useState<'invite' | 'password'>('invite');
  const [settings, setSettings] = useState<SettingDef[]>([]);
  const [draft, setDraft] = useState<Record<string, number | string>>({});
  const [integrations, setIntegrations] = useState<IntegrationRow[]>([]);
  const [tests, setTests] = useState<Record<string, IntegrationTestResult | 'running'>>({});
  const [matrix, setMatrix] = useState<PermissionRow[]>([]);

  // audit
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [search, setSearch] = useState('');
  const [integrity, setIntegrity] = useState<{ valid: boolean; checked: number; first_bad_id: number | null } | null>(null);

  const loadUsers = useCallback(async () => {
    try { setUsers(await api.getUsers()); } catch (e: any) { setError(e.message); }
  }, []);

  const loadConfig = async () => {
    try {
      const [s, i, m] = await Promise.all([api.getSecuritySettings(), api.getIntegrations(), api.getPermissions()]);
      setSettings(s);
      setDraft(Object.fromEntries(s.map((x) => [x.key, x.value])));
      setIntegrations(i);
      setMatrix(m);
    } catch (e: any) { setError(e.message); }
  };

  const runTest = async (key: string) => {
    let to: string | undefined;
    if (key === 'sms') {
      to = window.prompt('Phone number to send a test text to (+15551234567). It may cost a few cents.')?.trim();
      if (!to) return;
    }
    setTests((t) => ({ ...t, [key]: 'running' }));
    try {
      const r = await api.testIntegration(key, to);
      setTests((t) => ({ ...t, [key]: r }));
    } catch (e: any) {
      setTests((t) => ({ ...t, [key]: { key, ok: false, detail: e.message, latency_ms: 0 } }));
    }
  };

  const loadAudit = useCallback(async () => {
    try { setEntries(await api.getAudit({ q: search.trim() || undefined, limit: 100 })); } catch (e: any) { setError(e.message); }
  }, [search]);

  useLoad(loadUsers, [loadUsers], { enabled: tab === 'users' });
  useLoad(loadAudit, [loadAudit], { enabled: tab === 'audit' });
  useLoad(loadConfig, [], { enabled: tab === 'config' });

  const act = async (label: string, fn: () => Promise<unknown>, after?: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(label);
      if (after) await after();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const createUser = (e: React.FormEvent) => {
    e.preventDefault();
    void act(mode === 'invite' ? `Created ${form.email}. An activation link was emailed so they can choose their own password.` : `Created ${form.email}. They must choose a new password at first sign-in.`, async () => {
      await api.createUser({
        email: form.email, full_name: form.full_name, role: form.role, department: form.department || undefined,
        ...(mode === 'invite' ? { send_invite: true } : { send_invite: false, temporary_password: form.temporary_password }),
      });
      setForm({ email: '', full_name: '', role: 'SOC Analyst', department: '', temporary_password: '' });
    }, loadUsers);
  };

  const tabBtn = (id: 'users' | 'audit' | 'config', label: string) => (
    <button onClick={() => setTab(id)} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${tab === id ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
      {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <div className="pb-2 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-sky-500" /> Administration
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Accounts, access and the tamper-evident audit trail</p>
      </div>

      <div className="flex gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        {tabBtn('users', 'Users')}
        {tabBtn('audit', 'Audit log')}
        {tabBtn('config', 'Security configuration')}
      </div>

      {error && <div role="alert" className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">{error}</div>}
      {notice && <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-xs">{notice}</div>}

      {tab === 'users' && (
        <>
          <form onSubmit={createUser} className={card + ' p-4 grid gap-3 md:grid-cols-6 items-end'}>
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 md:col-span-2">Work email
              <input required type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className={field + ' w-full mt-1'} />
            </label>
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 md:col-span-2">Full name
              <input required value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} className={field + ' w-full mt-1'} />
            </label>
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Role
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className={field + ' w-full mt-1'}>
                {roleChoices.map((r) => <option key={r}>{r}</option>)}
              </select>
            </label>
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Department
              <input value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })} className={field + ' w-full mt-1'} />
            </label>
            <fieldset className="md:col-span-3 text-xs text-slate-700 dark:text-slate-300">
              <legend className="font-semibold mb-1">How they get access</legend>
              <label className="mr-4"><input type="radio" checked={mode === 'invite'} onChange={() => setMode('invite')} /> Email an activation link (recommended)</label>
              <label><input type="radio" checked={mode === 'password'} onChange={() => setMode('password')} /> Set a temporary password</label>
              {mode === 'password' && <input required minLength={12} type="text" autoComplete="off" placeholder="12+ characters" value={form.temporary_password} onChange={(e) => setForm({ ...form, temporary_password: e.target.value })} className={field + ' w-full mt-1 font-mono'} />}
            </fieldset>
            <div className="md:col-span-3 flex items-end">
              <button disabled={busy} className="flex items-center gap-1.5 px-3.5 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
                <UserPlus className="w-3.5 h-3.5" /> Create user
              </button>
            </div>
          </form>

          <div className={card + ' overflow-hidden'}>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">User</th><th className="py-3 px-4">Role</th><th className="py-3 px-4">MFA</th>
                    <th className="py-3 px-4">Last sign-in</th><th className="py-3 px-4">Status</th><th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {users.map((u) => {
                    const self = u.id === currentUser.id;
                    return (
                      <tr key={u.id}>
                        <td className="py-3 px-4"><div className="font-semibold text-slate-900 dark:text-white">{u.full_name}</div><div className="text-slate-500 font-mono">{u.email}</div></td>
                        <td className="py-3 px-4">
                          <select disabled={self || busy || (!isSuper && !['SOC Analyst', 'Employee'].includes(u.role))} value={u.role}
                            onChange={(e) => void act(`Role for ${u.email} is now ${e.target.value}. Their sessions were signed out.`, () => api.updateUser(u.id, { role: e.target.value }), loadUsers)}
                            className={field}>
                            {roleChoices.concat(roleChoices.includes(u.role) ? [] : [u.role]).map((r) => <option key={r}>{r}</option>)}
                          </select>
                        </td>
                        <td className="py-3 px-4">{u.mfa_enabled ? <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400"><BadgeCheck className="w-3.5 h-3.5" />On</span> : <span className="text-slate-500">Off</span>}</td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400">{when(u.last_login)}</td>
                        <td className="py-3 px-4">{u.is_active ? 'Active' : <span className="text-red-600 dark:text-red-400 font-semibold">Deactivated</span>}</td>
                        <td className="py-3 px-4 text-right whitespace-nowrap space-x-3">
                          {!u.last_login && <button disabled={busy} onClick={() => void act(`Activation link re-sent to ${u.email}.`, () => api.resendInvite(u.id))} className="text-violet-600 dark:text-violet-400 font-semibold hover:underline disabled:opacity-50">Resend invite</button>}
                          <button disabled={busy} onClick={() => void act(`MFA reset for ${u.email}. They must enrol again.`, () => api.resetUserMfa(u.id), loadUsers)} className="text-sky-600 dark:text-sky-400 font-semibold hover:underline disabled:opacity-50">Reset MFA</button>
                          <button disabled={busy} onClick={() => void act(`Signed ${u.email} out everywhere.`, () => api.revokeUserSessions(u.id))} className="text-sky-600 dark:text-sky-400 font-semibold hover:underline disabled:opacity-50">Sign out</button>
                          {!self && (
                            <button disabled={busy} onClick={() => void act(`${u.email} is now ${u.is_active ? 'deactivated' : 'active'}.`, () => api.updateUser(u.id, { is_active: !u.is_active }), loadUsers)}
                              className={`font-semibold hover:underline disabled:opacity-50 ${u.is_active ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                              {u.is_active ? 'Deactivate' : 'Reactivate'}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {tab === 'audit' && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search actor, action or details…" className={field + ' pl-9 w-72'} />
            </div>
            <button onClick={() => void loadAudit()} aria-label="Refresh" className="p-1.5 text-slate-500 hover:text-sky-600"><RefreshCw className="w-4 h-4" /></button>
            {isSuper && (
              <button disabled={busy} onClick={() => void act('Integrity check finished.', async () => setIntegrity(await api.verifyAudit()))}
                className="ml-auto flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 dark:bg-slate-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">
                <ShieldCheck className="w-3.5 h-3.5" /> Verify integrity
              </button>
            )}
          </div>

          {integrity && (
            <div className={`p-3 rounded-lg text-xs flex items-center gap-2 border ${integrity.valid ? 'bg-emerald-50 dark:bg-emerald-950/50 border-emerald-200 dark:border-emerald-900 text-emerald-800 dark:text-emerald-300' : 'bg-red-50 dark:bg-red-950/50 border-red-200 dark:border-red-900 text-red-700 dark:text-red-300'}`}>
              {integrity.valid ? <BadgeCheck className="w-4 h-4" /> : <TriangleAlert className="w-4 h-4" />}
              {integrity.valid
                ? `The chain is intact: ${integrity.checked} entries checked, none altered.`
                : `The chain is BROKEN at entry #${integrity.first_bad_id}: that entry or an earlier one was changed or removed.`}
            </div>
          )}

          <div className={card + ' overflow-hidden'}>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">When</th><th className="py-3 px-4">Actor</th><th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Target</th><th className="py-3 px-4">Details</th><th className="py-3 px-4">From</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {entries.length === 0 && <tr><td colSpan={6} className="py-8 text-center text-slate-500">No entries match.</td></tr>}
                  {entries.map((a) => (
                    <tr key={a.id} title={a.request_id ? `Request ${a.request_id}` : undefined}>
                      <td className="py-2.5 px-4 font-mono text-slate-600 dark:text-slate-400 whitespace-nowrap">{when(a.timestamp)}</td>
                      <td className="py-2.5 px-4 text-slate-900 dark:text-white break-all">{a.actor}</td>
                      <td className="py-2.5 px-4 font-semibold text-slate-800 dark:text-slate-200">{a.action}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-600 dark:text-slate-400 break-all">{a.resource_type} {a.resource_id}</td>
                      <td className="py-2.5 px-4 text-slate-600 dark:text-slate-400 max-w-md">{a.details}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-500">{a.ip_address ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {tab === 'config' && (
        <div className="space-y-6">
          <section className={card + ' p-4 space-y-4'}>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">Severity thresholds and alerting</h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">Applied by the automated triage tier. Every change is audited.</p>
            </div>
            <form onSubmit={(e) => { e.preventDefault(); const changed = Object.fromEntries(Object.entries(draft).filter(([k, v]) => settings.find((s) => s.key === k)?.value !== v)); if (Object.keys(changed).length) void act('Configuration saved.', () => api.putSecuritySettings(changed), loadConfig); }} className="grid gap-4 md:grid-cols-2">
              {settings.map((s) => (
                <label key={s.key} className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  {s.label}
                  {s.type === 'int'
                    ? <input type="number" min={s.min} max={s.max} value={draft[s.key] ?? ''} onChange={(e) => setDraft({ ...draft, [s.key]: Number(e.target.value) })} className={field + ' w-full mt-1'} />
                    : <select value={String(draft[s.key] ?? '')} onChange={(e) => setDraft({ ...draft, [s.key]: e.target.value })} className={field + ' w-full mt-1'}>{s.choices?.map((c) => <option key={c}>{c}</option>)}</select>}
                  <span className="block font-normal text-[11px] text-slate-500 mt-0.5">{s.help}{s.min !== undefined ? ` (${s.min}–${s.max}, default ${s.default})` : ` (default ${s.default})`}{s.updated_by ? ` Last changed by ${s.updated_by}.` : ''}</span>
                </label>
              ))}
              <div className="md:col-span-2"><button disabled={busy} className="px-3.5 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">Save configuration</button></div>
            </form>
          </section>

          <section className={card + ' p-4 space-y-3'}>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">Security integrations</h2>
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {integrations.map((i) => {
                const t = i.key ? tests[i.key] : undefined;
                const tested = t && t !== 'running' ? t : undefined;
                const dot = tested ? (tested.ok ? 'bg-emerald-500' : 'bg-red-500') : i.state === 'connected' ? 'bg-emerald-500' : i.configured ? 'bg-amber-400' : 'bg-slate-300 dark:bg-slate-600';
                const label = tested ? (tested.ok ? 'Test passed' : 'Test failed') : i.state === 'connected' ? 'Connected' : i.configured ? 'Configured, not verified' : 'Not set up';
                return (
                  <li key={i.name} className="py-2 text-xs flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className={`w-2 h-2 rounded-full ${dot}`} />
                    <span className="font-semibold text-slate-900 dark:text-white w-64">{i.name}</span>
                    <span className="text-slate-500 flex-1 min-w-[16rem]">
                      {label} · {tested ? `${tested.detail} (${tested.latency_ms} ms)` : i.detail}{i.synthetic ? ' · data marked simulated' : ''}
                    </span>
                    {i.key && (
                      <button disabled={t === 'running'} onClick={() => void runTest(i.key!)}
                        className="px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 font-semibold hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50">
                        {t === 'running' ? 'Testing…' : 'Test'}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
            <p className="text-[11px] text-slate-500">Credentials are set in the server environment, never in the browser. Firewall feed credentials are managed on the Blocklist page; alert rules on SOC Operations.</p>
          </section>

          <section className={card + ' overflow-hidden'}>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white p-4 pb-2">Role permissions</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead><tr className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[11px]"><th className="py-2 px-4">Capability</th>{ROLES.map((r) => <th key={r} className="py-2 px-3">{r}</th>)}</tr></thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {matrix.map((m) => (
                    <tr key={m.capability}>
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200">{m.capability}</td>
                      {ROLES.map((r) => <td key={r} className="py-2 px-3">{m[r] === true ? <span className="text-emerald-600 dark:text-emerald-400 font-bold">Yes</span> : m[r] === false ? <span className="text-slate-300 dark:text-slate-600">—</span> : <span className="text-amber-600 dark:text-amber-400">{String(m[r])}</span>}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
