import React, { useEffect, useState } from 'react';
import {
  ShieldCheck, Lock, Mail, AlertTriangle, CheckCircle2, Eye, EyeOff, Sun, Moon, KeyRound
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { api } from '../api/client';
import { useTheme } from '../context/themeContext';
import { SessionState, UserSession } from '../types';

interface LoginPageProps {
  /** A session that exists but isn't complete yet (MFA or forced password change pending). */
  resume?: SessionState | null;
  onLoginSuccess: (user: UserSession) => void;
}

type Stage = 'credentials' | 'mfa_verify' | 'mfa_enroll' | 'change_password' | 'forgot' | 'reset';

const inputClass =
  'w-full pl-9 pr-3 py-2.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500 transition';
const buttonClass =
  'w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 text-white font-semibold text-xs shadow-md transition flex items-center justify-center gap-2 disabled:opacity-50';

export const LoginPage: React.FC<LoginPageProps> = ({ resume, onLoginSuccess }) => {
  const { theme, toggleTheme } = useTheme();
  const params = new URLSearchParams(window.location.search);
  const resetToken = params.get('reset_token');
  const activating = params.get('activate') === '1';

  const [stage, setStage] = useState<Stage>(resetToken ? 'reset' : 'credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [sso, setSso] = useState<{ enabled: boolean; provider_name: string } | null>(null);
  const ssoRefused = params.get('sso_error') === 'denied';

  const enterStage = async (state: SessionState) => {
    setError(null);
    setCode('');
    if (state.mfa_state === 'verify') return setStage('mfa_verify');
    if (state.mfa_state === 'enroll') {
      setStage('mfa_enroll');
      try {
        setEnrol(await api.mfaSetup());
      } catch (e: any) {
        setError(e.message);
      }
      return;
    }
    if (state.must_change_password) return setStage('change_password');
    onLoginSuccess(state.user);
  };

  useEffect(() => {
    api.ssoConfig().then(setSso).catch(() => setSso(null));
    if (ssoRefused) {
      window.history.replaceState({}, '', window.location.pathname);
      setError('Single sign-on was refused. Your account may not exist here or may be disabled; ask your security administrator.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (resume) void enterStage(resume);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resume]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e: any) {
      setError(e.message || 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  };

  const submitCredentials = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const state = await api.login({ email: email.trim(), password });
      setPassword('');
      await enterStage(state);
    });
  };

  const submitCode = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const state = stage === 'mfa_enroll' ? await api.mfaEnable(code) : await api.mfaVerify(code);
      await enterStage(state);
    });
  };

  const submitNewPassword = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.changePassword({ current_password: password, new_password: newPassword });
      const state = await api.getMe();
      setPassword('');
      setNewPassword('');
      await enterStage(state);
    });
  };

  const submitForgot = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res = await api.forgotPassword(email.trim());
      setNotice(res.message);
      setStage('credentials');
    });
  };

  const submitReset = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res = await api.resetPassword({ token: resetToken!, new_password: newPassword });
      window.history.replaceState({}, '', window.location.pathname);
      setNewPassword('');
      setNotice(res.message);
      setStage('credentials');
    });
  };

  const field = (label: string, icon: React.ReactNode, input: React.ReactNode) => (
    <div>
      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">{label}</label>
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">{icon}</div>
        {input}
      </div>
    </div>
  );

  const submit = (label: string) => (
    <button type="submit" disabled={busy} className={buttonClass}>
      {busy ? <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" /> : null}
      <span>{label}</span>
    </button>
  );

  const titles: Record<Stage, [string, string]> = {
    credentials: ['Welcome Back', 'Sign in to your CYBERSHIELD AI account'],
    mfa_verify: ['Two-step verification', 'Enter the 6-digit code from your authenticator app'],
    mfa_enroll: ['Set up two-step verification', 'Your role requires an authenticator app before you can continue'],
    change_password: ['Choose a new password', 'You must replace your temporary password before continuing'],
    forgot: ['Reset your password', "We'll email you a link that works once, for 30 minutes"],
    reset: activating
      ? ['Activate your account', 'Choose a password to finish setting up your CYBERSHIELD AI account']
      : ['Choose a new password', 'Pick a password you do not use anywhere else'],
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center p-4 sm:p-6 font-sans relative transition-colors duration-200">
      <div className="absolute top-4 right-4 z-20">
        <button
          onClick={toggleTheme}
          className="p-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition shadow-sm"
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
        >
          {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4 text-amber-400" />}
        </button>
      </div>

      <div className="w-full max-w-5xl rounded-2xl overflow-hidden shadow-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col md:flex-row min-h-[620px]">
        {/* Left Side: Cyber Shield Brand Hero */}
        <div className="w-full md:w-5/12 bg-gradient-to-br from-sky-900 via-slate-900 to-sky-950 p-8 sm:p-12 text-white flex flex-col justify-between relative overflow-hidden">
          {/* Subtle Cyber Grid Background & Glow Rings */}
          <div className="absolute inset-0 bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:20px_20px] opacity-15 pointer-events-none" />
          <div className="absolute -top-24 -left-24 w-80 h-80 bg-sky-500/20 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-24 -right-24 w-80 h-80 bg-indigo-500/20 rounded-full blur-3xl pointer-events-none" />

          {/* Brand Header */}
          <div className="relative z-10">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-xl bg-sky-500 flex items-center justify-center text-white shadow-lg shadow-sky-500/30">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
                  CYBERSHIELD <span className="text-sky-400">AI</span>
                </h1>
                <p className="text-[11px] text-sky-300 tracking-wider font-medium">
                  Detect • Prevent • Investigate • Secure
                </p>
              </div>
            </div>
          </div>

          {/* Center Graphic: Futuristic Holographic Shield / Globe */}
          <div className="my-8 relative z-10 flex flex-col items-center text-center">
            <div className="w-44 h-44 rounded-full border-2 border-sky-400/40 p-3 flex items-center justify-center relative shadow-inner">
              <div className="w-36 h-36 rounded-full border border-sky-300/30 flex items-center justify-center animate-pulse">
                <div className="w-28 h-28 rounded-full bg-sky-600/20 backdrop-blur-xs flex items-center justify-center shadow-2xl shadow-sky-500/50">
                  <ShieldCheck className="w-14 h-14 text-sky-400" />
                </div>
              </div>
              {/* Outer Orbit Rings */}
              <div className="absolute inset-0 rounded-full border border-dashed border-sky-400/30 animate-spin" style={{ animationDuration: '30s' }} />
            </div>

            <h2 className="text-xl font-bold text-white mt-6 tracking-tight">
              Smarter Security for a Safer Tomorrow
            </h2>
            <p className="text-xs text-sky-200/80 mt-2 max-w-xs leading-relaxed">
              AI-powered threat detection, real-time monitoring and enterprise data protection.
            </p>
          </div>

          {/* Footer Info */}
          <div className="relative z-10 pt-4 border-t border-sky-800/40 text-[11px] text-sky-300/70 flex items-center justify-between">
            <span>Enterprise 24/7 SOC</span>
            <span className="font-mono">v2.0.0</span>
          </div>
        </div>

        <div className="w-full md:w-7/12 p-8 sm:p-12 flex flex-col justify-center bg-white dark:bg-slate-900 transition-colors">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-6">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">{titles[stage][0]}</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{titles[stage][1]}</p>
            </div>

            {error && (
              <div role="alert" className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}
            {notice && (
              <div className="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-xs flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{notice}</span>
              </div>
            )}

            {stage === 'credentials' && (
              <form onSubmit={submitCredentials} className="space-y-4">
                {field('Email address', <Mail className="w-4 h-4" />,
                  <input type="email" required autoComplete="username" value={email}
                    onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} />)}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Password</label>
                    <button type="button" onClick={() => { setError(null); setNotice(null); setStage('forgot'); }}
                      className="text-xs text-sky-600 dark:text-sky-400 hover:underline">
                      Forgot password?
                    </button>
                  </div>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400"><Lock className="w-4 h-4" /></div>
                    <input type={showPassword ? 'text' : 'password'} required autoComplete="current-password" value={password}
                      onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" className={inputClass + ' pr-10'} />
                    <button type="button" onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                {submit('Sign In')}
                {sso?.enabled && (
                  <>
                    <div className="flex items-center gap-3 text-[11px] text-slate-400"><span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />or<span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" /></div>
                    <a href={api.ssoLoginUrl()}
                      className="w-full py-2.5 px-4 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 font-semibold text-xs transition flex items-center justify-center gap-2">
                      <Lock className="w-4 h-4" /> Continue with {sso.provider_name}
                    </a>
                  </>
                )}
                <p className="text-center text-xs text-slate-500 dark:text-slate-400 pt-2">
                  Need access? Ask your security administrator to create your account.
                </p>
              </form>
            )}

            {(stage === 'mfa_verify' || stage === 'mfa_enroll') && (
              <form onSubmit={submitCode} className="space-y-4">
                {stage === 'mfa_enroll' && enrol && (
                  <div className="flex flex-col items-center gap-3 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
                    <div className="bg-white p-2 rounded"><QRCodeSVG value={enrol.otpauth_uri} size={152} /></div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 text-center">
                      Scan with an authenticator app, or enter this key manually:
                    </p>
                    <code className="text-xs font-mono break-all text-slate-800 dark:text-slate-200 select-all">{enrol.secret}</code>
                  </div>
                )}
                {field('6-digit code', <KeyRound className="w-4 h-4" />,
                  <input inputMode="numeric" pattern="[0-9]*" maxLength={6} required autoComplete="one-time-code" autoFocus
                    value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} placeholder="123456"
                    className={inputClass + ' font-mono tracking-widest'} />)}
                {submit(stage === 'mfa_enroll' ? 'Turn on and continue' : 'Verify')}
                <button type="button" onClick={() => { void api.logout().catch(() => undefined); setStage('credentials'); setEnrol(null); }}
                  className="w-full text-xs text-slate-500 hover:underline">Cancel and sign out</button>
              </form>
            )}

            {stage === 'change_password' && (
              <form onSubmit={submitNewPassword} className="space-y-4">
                {field('Temporary password', <Lock className="w-4 h-4" />,
                  <input type="password" required autoComplete="current-password" value={password}
                    onChange={(e) => setPassword(e.target.value)} className={inputClass} />)}
                {field('New password (12+ characters)', <Lock className="w-4 h-4" />,
                  <input type="password" required minLength={12} autoComplete="new-password" value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)} className={inputClass} />)}
                {submit('Change password')}
              </form>
            )}

            {stage === 'forgot' && (
              <form onSubmit={submitForgot} className="space-y-4">
                {field('Company email', <Mail className="w-4 h-4" />,
                  <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className={inputClass} />)}
                {submit('Email me a reset link')}
                <button type="button" onClick={() => setStage('credentials')} className="w-full text-xs text-slate-500 hover:underline">
                  Back to sign in
                </button>
              </form>
            )}

            {stage === 'reset' && (
              <form onSubmit={submitReset} className="space-y-4">
                {field('New password (12+ characters)', <Lock className="w-4 h-4" />,
                  <input type="password" required minLength={12} autoComplete="new-password" value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)} className={inputClass} />)}
                {submit(activating ? 'Activate account' : 'Set new password')}
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
