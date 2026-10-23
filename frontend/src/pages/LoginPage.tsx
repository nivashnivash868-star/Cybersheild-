import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, Lock, Mail, KeyRound, AlertTriangle, CheckCircle2,
  ArrowRight, Eye, EyeOff, Sparkles, Building2, Sun, Moon
} from 'lucide-react';
import { api, setAuthToken } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { UserSession, DemoAccount, UserRole } from '../types';

interface LoginPageProps {
  onLoginSuccess: (user: UserSession) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const { theme, toggleTheme } = useTheme();
  const [email, setEmail] = useState('admin@cybershield.corp');
  const [password, setPassword] = useState('CyberShield@2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [demoAccounts, setDemoAccounts] = useState<DemoAccount[]>([]);
  const [showResetModal, setShowResetModal] = useState(false);
  const [showSSOModal, setShowSSOModal] = useState<'google' | 'microsoft' | null>(null);
  const [customSSOEmail, setCustomSSOEmail] = useState('');
  const [resetEmail, setResetEmail] = useState('');
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [resetSuccessMsg, setResetSuccessMsg] = useState<string | null>(null);
  const [resetLoading, setResetLoading] = useState(false);

  useEffect(() => {
    const loadDemoAccounts = async () => {
      try {
        const accounts = await api.getDemoAccounts();
        setDemoAccounts(accounts);
      } catch (err) {
        console.error('Failed to load demo accounts:', err);
      }
    };
    loadDemoAccounts();
  }, []);

  const handleLogin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const loginEmail = email.trim() || 'admin@cybershield.corp';
    const loginPassword = password || 'CyberShield@2026!';

    setIsLoading(true);
    setErrorMsg(null);

    try {
      const session = await api.login({ email: loginEmail, password: loginPassword });
      setAuthToken(session.access_token);
      onLoginSuccess(session);
    } catch (err: any) {
      setErrorMsg(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSSOLogin = async (provider: 'google' | 'microsoft', accountEmail: string, name?: string) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const session = await api.loginWithSSO({
        provider,
        email: accountEmail,
        name,
      });
      setAuthToken(session.access_token);
      setShowSSOModal(null);
      onLoginSuccess(session);
    } catch (err: any) {
      setErrorMsg(err.message || `${provider} SSO authentication failed.`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectDemoAccount = (account: DemoAccount) => {
    setEmail(account.email);
    setPassword(account.password);
    setErrorMsg(null);
  };

  const handleQuickLoginAs = async (account: DemoAccount) => {
    setEmail(account.email);
    setPassword(account.password);
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const session = await api.login({ email: account.email, password: account.password });
      setAuthToken(session.access_token);
      onLoginSuccess(session);
    } catch (err: any) {
      setErrorMsg(err.message || 'Quick login failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetEmail) return;
    setResetLoading(true);
    setResetSuccessMsg(null);
    try {
      const res = await api.resetPassword({
        email: resetEmail.trim(),
        new_password: resetNewPassword || undefined,
      });
      setResetSuccessMsg(res.message);
      setTimeout(() => {
        setPassword(resetNewPassword || 'CyberShield@2026!');
        setEmail(resetEmail);
        setShowResetModal(false);
        setResetSuccessMsg(null);
      }, 2000);
    } catch (err: any) {
      alert(`Reset error: ${err.message}`);
    } finally {
      setResetLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center p-4 sm:p-6 font-sans relative transition-colors duration-200">
      {/* Theme Toggle Button at top-right */}
      <div className="absolute top-4 right-4 z-20">
        <button
          onClick={toggleTheme}
          className="p-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition shadow-sm"
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
        >
          {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4 text-amber-400" />}
        </button>
      </div>

      {/* Main Container - Split View matching User's Screen 1 */}
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

        {/* Right Side: Sign-In Card matching User's Mockup */}
        <div className="w-full md:w-7/12 p-8 sm:p-12 flex flex-col justify-center bg-white dark:bg-slate-900 transition-colors">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-6">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                Welcome Back
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Sign in to your CYBERSHIELD AI account
              </p>
            </div>

            {errorMsg && (
              <div className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600 dark:text-red-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Email address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full pl-9 pr-3 py-2.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500 transition"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setResetEmail(email || 'admin@cybershield.corp');
                      setShowResetModal(true);
                    }}
                    className="text-xs text-sky-600 dark:text-sky-400 hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    className="w-full pl-9 pr-10 py-2.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500 transition"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded text-sky-600 focus:ring-sky-500 border-slate-300 dark:border-slate-600 w-4 h-4"
                  />
                  <span className="text-xs text-slate-600 dark:text-slate-400 select-none">Remember me</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 text-white font-semibold text-xs shadow-md transition flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Signing in...</span>
                  </>
                ) : (
                  <span>Sign In</span>
                )}
              </button>
            </form>

            {/* Social Logins as in mockup */}
            <div className="mt-5 text-center">
              <div className="relative my-3">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-200 dark:border-slate-800" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-white dark:bg-slate-900 px-3 text-slate-400 text-[11px]">
                    or continue with
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 mt-3">
                <button
                  type="button"
                  onClick={() => setShowSSOModal('google')}
                  className="flex items-center justify-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition shadow-2xs hover:border-sky-400"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                  </svg>
                  <span>Google</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowSSOModal('microsoft')}
                  className="flex items-center justify-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition shadow-2xs hover:border-sky-400"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24">
                    <path fill="#F25022" d="M1 1h10v10H1z" />
                    <path fill="#00A4EF" d="M1 13h10v10H1z" />
                    <path fill="#7FBA00" d="M13 1h10v10H13z" />
                    <path fill="#FFB900" d="M13 13h10v10H13z" />
                  </svg>
                  <span>Microsoft</span>
                </button>
              </div>
            </div>

            {/* 1-Click Role Logins for seamless testing */}
            <div className="mt-5 pt-4 border-t border-slate-100 dark:border-slate-800">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">
                1-Click Role Access (Demo Ready)
              </p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {demoAccounts.map((acc) => (
                  <button
                    key={acc.role}
                    type="button"
                    onClick={() => handleQuickLoginAs(acc)}
                    className="p-2 text-left rounded-lg border border-slate-200 dark:border-slate-700 hover:border-sky-500 dark:hover:border-sky-400 hover:bg-sky-50/50 dark:hover:bg-sky-950/30 transition group"
                  >
                    <div className="font-semibold text-slate-800 dark:text-slate-200 text-[11px] group-hover:text-sky-600 dark:group-hover:text-sky-400">
                      {acc.role}
                    </div>
                    <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate">{acc.name}</div>
                  </button>
                ))}
              </div>
            </div>

            <p className="text-center text-xs text-slate-500 dark:text-slate-400 mt-6">
              Don't have an account?{' '}
              <span className="text-sky-600 dark:text-sky-400 font-medium cursor-pointer hover:underline">
                Contact your administrator
              </span>
            </p>
          </div>
        </div>
      </div>

      {/* Enterprise Single Sign-On (Google Workspace / Microsoft Entra ID) Modal */}
      {showSSOModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2.5">
                {showSSOModal === 'google' ? (
                  <svg className="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="#F25022" d="M1 1h10v10H1z" />
                    <path fill="#00A4EF" d="M1 13h10v10H1z" />
                    <path fill="#7FBA00" d="M13 1h10v10H13z" />
                    <path fill="#FFB900" d="M13 13h10v10H13z" />
                  </svg>
                )}
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  {showSSOModal === 'google' ? 'Google Workspace SSO' : 'Microsoft Entra ID SSO'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowSSOModal(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs font-semibold"
              >
                Cancel
              </button>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-4">
              Select an authorized corporate identity to sign in to CYBERSHIELD AI:
            </p>

            <div className="space-y-2">
              {[
                {
                  name: 'Chief Information Security Officer',
                  email: 'admin@cybershield.corp',
                  role: 'Super Admin',
                  initials: 'CI',
                  color: 'bg-sky-600',
                },
                {
                  name: 'Rahul Kumar',
                  email: 'rahul.k@company.com',
                  role: 'Employee',
                  initials: 'RK',
                  color: 'bg-emerald-600',
                },
                {
                  name: 'Sarah Chen',
                  email: 'analyst@cybershield.corp',
                  role: 'SOC Analyst',
                  initials: 'SC',
                  color: 'bg-indigo-600',
                },
                {
                  name: 'David Vance',
                  email: 'secadmin@cybershield.corp',
                  role: 'Security Administrator',
                  initials: 'DV',
                  color: 'bg-purple-600',
                },
              ].map((acc) => (
                <button
                  key={acc.email}
                  type="button"
                  disabled={isLoading}
                  onClick={() => handleSSOLogin(showSSOModal!, acc.email, acc.name)}
                  className="w-full p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-sky-500 dark:hover:border-sky-400 hover:bg-sky-50/50 dark:hover:bg-sky-950/30 flex items-center justify-between text-left transition group"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-full ${acc.color} text-white font-bold flex items-center justify-center text-xs shadow-xs`}>
                      {acc.initials}
                    </div>
                    <div>
                      <p className="font-semibold text-slate-900 dark:text-white text-xs group-hover:text-sky-600 dark:group-hover:text-sky-400">
                        {acc.name}
                      </p>
                      <p className="text-[11px] text-slate-400 font-mono">{acc.email}</p>
                    </div>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                    {acc.role}
                  </span>
                </button>
              ))}
            </div>

            {/* Custom SSO Email option */}
            <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800">
              <label className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1">
                Or enter another corporate email:
              </label>
              <div className="flex gap-2">
                <input
                  type="email"
                  placeholder="user@company.com"
                  value={customSSOEmail}
                  onChange={(e) => setCustomSSOEmail(e.target.value)}
                  className="flex-1 px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white outline-none focus:ring-1 focus:ring-sky-500"
                />
                <button
                  type="button"
                  disabled={!customSSOEmail.trim() || isLoading}
                  onClick={() => handleSSOLogin(showSSOModal!, customSSOEmail.trim())}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold disabled:opacity-50 transition"
                >
                  Sign In
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Password Reset Modal */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-700">
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1">Reset Account Password</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              Enter corporate email to verify identity and reset password.
            </p>

            {resetSuccessMsg ? (
              <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>{resetSuccessMsg}</span>
              </div>
            ) : (
              <form onSubmit={handlePasswordReset} className="space-y-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Company Email
                  </label>
                  <input
                    type="email"
                    required
                    value={resetEmail}
                    onChange={(e) => setResetEmail(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowResetModal(false)}
                    className="px-3 py-1.5 text-xs text-slate-600 dark:text-slate-400"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={resetLoading}
                    className="px-4 py-1.5 text-xs font-semibold bg-sky-600 text-white rounded-lg hover:bg-sky-700"
                  >
                    {resetLoading ? 'Resetting...' : 'Reset Password'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
