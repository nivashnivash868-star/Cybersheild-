import React, { useState } from 'react';
import { BadgeCheck, KeyRound, LogOut, ShieldCheck } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { api, UNAUTHORIZED_EVENT } from '../api/client';
import { UserSession } from '../types';

interface Props {
  currentUser: UserSession;
  onUpdateUser: (user: UserSession) => void;
}

const card = 'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 space-y-3';
const field = 'w-full px-3 py-2 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white';
const label = 'block text-xs font-semibold text-slate-700 dark:text-slate-300';
const primary = 'px-3.5 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50';

const Message: React.FC<{ kind: 'ok' | 'error'; children: React.ReactNode }> = ({ kind, children }) => (
  <p role={kind === 'error' ? 'alert' : 'status'} className={`text-xs ${kind === 'ok' ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>{children}</p>
);

/** Account settings: only things that really persist. System configuration lives under Administration. */
export const SettingsPage: React.FC<Props> = ({ currentUser, onUpdateUser }) => {
  const privileged = currentUser.role !== 'Employee';

  // profile
  const [name, setName] = useState(currentUser.name);
  const [department, setDepartment] = useState(currentUser.department === 'Security Operations' ? '' : currentUser.department);
  const [phone, setPhone] = useState('');
  const [profileMsg, setProfileMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);

  // password
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [pwMsg, setPwMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);

  // two-step verification
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [offPassword, setOffPassword] = useState('');
  const [mfaMsg, setMfaMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);
  const [showOff, setShowOff] = useState(false);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<void>, onError: (m: string) => void) => {
    setBusy(true);
    try { await fn(); } catch (e: any) { onError(e.message || 'Something went wrong.'); } finally { setBusy(false); }
  };

  const saveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const updated = await api.updateProfile({ full_name: name.trim() || undefined, department: department.trim() || undefined, phone_number: phone.trim() || undefined });
      onUpdateUser({ ...currentUser, name: updated.name, department: updated.department });
      setProfileMsg({ kind: 'ok', text: 'Profile saved.' });
    }, (m) => setProfileMsg({ kind: 'error', text: m }));
  };

  const changePassword = (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return setPwMsg({ kind: 'error', text: 'The new passwords do not match.' });
    void run(async () => {
      const res = await api.changePassword({ current_password: current, new_password: next });
      setCurrent(''); setNext(''); setConfirm('');
      setPwMsg({ kind: 'ok', text: res.message });
    }, (m) => setPwMsg({ kind: 'error', text: m }));
  };

  const startMfa = () => void run(async () => { setMfaMsg(null); setEnrol(await api.mfaSetup()); }, (m) => setMfaMsg({ kind: 'error', text: m }));

  const confirmMfa = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const state = await api.mfaEnable(code);
      onUpdateUser(state.user);
      setEnrol(null); setCode('');
      setMfaMsg({ kind: 'ok', text: 'Two-step verification is on. Your other sessions were signed out.' });
    }, (m) => setMfaMsg({ kind: 'error', text: m }));
  };

  const turnOffMfa = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.mfaDisable(offPassword, code);
      onUpdateUser({ ...currentUser, mfa_enabled: false });
      setShowOff(false); setOffPassword(''); setCode('');
      setMfaMsg({ kind: 'ok', text: 'Two-step verification is off.' });
    }, (m) => setMfaMsg({ kind: 'error', text: m }));
  };

  const signOutEverywhere = () => void run(async () => {
    await api.logoutAll();
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }, (m) => setMfaMsg({ kind: 'error', text: m }));

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="pb-2 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Account settings</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          {currentUser.email} · {currentUser.role}.{privileged && ' Alert thresholds, integrations and accounts are managed by administrators.'}
        </p>
      </div>

      <form onSubmit={saveProfile} className={card}>
        <h2 className="text-sm font-bold text-slate-900 dark:text-white">Profile</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className={label}>Full name<input value={name} onChange={(e) => setName(e.target.value)} required className={field + ' mt-1'} /></label>
          <label className={label}>Department<input value={department} onChange={(e) => setDepartment(e.target.value)} className={field + ' mt-1'} /></label>
          <label className={label}>Mobile number for SMS alerts<input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+15551234567" className={field + ' mt-1 font-mono'} />
            <span className="font-normal text-[11px] text-slate-500">International format. Leave empty to keep the current number.</span></label>
        </div>
        <div className="flex items-center gap-3"><button disabled={busy} className={primary}>Save profile</button>{profileMsg && <Message kind={profileMsg.kind}>{profileMsg.text}</Message>}</div>
      </form>

      <section className={card}>
        <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> Two-step verification</h2>
        {currentUser.mfa_enabled ? (
          <>
            <p className="text-xs text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5"><BadgeCheck className="w-4 h-4" /> On. You enter a code from your authenticator app when you sign in.</p>
            {!showOff ? (
              <button onClick={() => { setShowOff(true); setMfaMsg(null); }} className="text-xs font-semibold text-red-600 dark:text-red-400 hover:underline">Turn off…</button>
            ) : (
              <form onSubmit={turnOffMfa} className="space-y-2">
                <label className={label}>Your password<input type="password" required value={offPassword} onChange={(e) => setOffPassword(e.target.value)} className={field + ' mt-1'} autoComplete="current-password" /></label>
                <label className={label}>Current 6-digit code<input inputMode="numeric" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} className={field + ' mt-1 font-mono'} autoComplete="one-time-code" /></label>
                <div className="flex gap-3"><button disabled={busy} className={primary}>Turn off</button><button type="button" onClick={() => setShowOff(false)} className="text-xs text-slate-500">Cancel</button></div>
              </form>
            )}
            {privileged && <p className="text-[11px] text-slate-500">Administrators and analysts can't turn this off when the platform requires it.</p>}
          </>
        ) : !enrol ? (
          <>
            <p className="text-xs text-slate-600 dark:text-slate-400">Add a second step so a stolen password alone can't sign in as you.</p>
            <button disabled={busy} onClick={startMfa} className={primary}>Set up two-step verification</button>
          </>
        ) : (
          <form onSubmit={confirmMfa} className="space-y-3">
            <div className="flex flex-col sm:flex-row items-center gap-4">
              <div className="bg-white p-2 rounded"><QRCodeSVG value={enrol.otpauth_uri} size={140} /></div>
              <div className="text-xs text-slate-600 dark:text-slate-400 space-y-2">
                <p>Scan with an authenticator app, or enter this key manually:</p>
                <code className="block font-mono break-all text-slate-900 dark:text-white select-all">{enrol.secret}</code>
              </div>
            </div>
            <label className={label}>6-digit code<input inputMode="numeric" maxLength={6} required autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} className={field + ' mt-1 font-mono tracking-widest max-w-40'} autoComplete="one-time-code" /></label>
            <div className="flex gap-3"><button disabled={busy} className={primary}>Turn on</button><button type="button" onClick={() => { setEnrol(null); setCode(''); }} className="text-xs text-slate-500">Cancel</button></div>
          </form>
        )}
        {mfaMsg && <Message kind={mfaMsg.kind}>{mfaMsg.text}</Message>}
      </section>

      <form onSubmit={changePassword} className={card}>
        <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><KeyRound className="w-4 h-4" /> Password</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className={label}>Current<input type="password" required value={current} onChange={(e) => setCurrent(e.target.value)} className={field + ' mt-1'} autoComplete="current-password" /></label>
          <label className={label}>New (12+ characters)<input type="password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} className={field + ' mt-1'} autoComplete="new-password" /></label>
          <label className={label}>Repeat new<input type="password" required minLength={12} value={confirm} onChange={(e) => setConfirm(e.target.value)} className={field + ' mt-1'} autoComplete="new-password" /></label>
        </div>
        <div className="flex items-center gap-3"><button disabled={busy} className={primary}>Change password</button>{pwMsg && <Message kind={pwMsg.kind}>{pwMsg.text}</Message>}</div>
        <p className="text-[11px] text-slate-500">Changing it signs you out of every other device.</p>
      </form>

      <section className={card}>
        <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2"><LogOut className="w-4 h-4" /> Sessions</h2>
        <p className="text-xs text-slate-600 dark:text-slate-400">Sign out of this device and every other one you're signed in on.</p>
        <button disabled={busy} onClick={signOutEverywhere} className="px-3.5 py-2 bg-slate-800 dark:bg-slate-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50">Sign out everywhere</button>
      </section>
    </div>
  );
};
