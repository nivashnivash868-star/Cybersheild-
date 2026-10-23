import React, { useState } from 'react';
import {
  Settings, Shield, Bell, Network, Users, Check,
  Sliders, Lock, Save, RefreshCw, KeyRound, Globe, User as UserIcon,
  CheckCircle2, Smartphone, AlertTriangle
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { UserSession } from '../types';
import { api } from '../api/client';

interface SettingsPageProps {
  currentUser?: UserSession | null;
  onUpdateUser?: (updated: UserSession) => void;
  initialTab?: 'profile' | 'monitoring' | 'general' | 'notifications' | 'integrations' | 'users';
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  currentUser,
  onUpdateUser,
  initialTab = 'profile',
}) => {
  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState<'profile' | 'monitoring' | 'general' | 'notifications' | 'integrations' | 'users'>(initialTab);
  const [savedMsg, setSavedMsg] = useState(false);

  // Profile form state
  const [profName, setProfName] = useState(currentUser?.name || 'Chief Information Security Officer');
  const [profDept, setProfDept] = useState(currentUser?.department || 'Executive Security Office');
  const [profPhone, setProfPhone] = useState('+1 (555) 942-8321');
  const [profTimezone, setProfTimezone] = useState('Asia/Kolkata (UTC+05:30)');
  const [profSaving, setProfSaving] = useState(false);
  const [profSuccess, setProfSuccess] = useState<string | null>(null);

  // Password state in profile tab
  const [curPassword, setCurPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwMsg, setPwMsg] = useState<string | null>(null);

  // Toggle settings matching Screen 13
  const [toggles, setToggles] = useState({
    monitorWebActivity: true,
    scanEmailPhishing: true,
    detectSensitiveData: true,
    monitorFileUploads: true,
    enableRealTimeAlerts: true,
  });

  const handleToggle = (key: keyof typeof toggles) => {
    setToggles((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = () => {
    setSavedMsg(true);
    setTimeout(() => setSavedMsg(false), 2000);
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfSaving(true);
    setProfSuccess(null);
    try {
      const updated = await api.updateProfile({
        full_name: profName.trim(),
        department: profDept.trim(),
        phone_number: profPhone.trim(),
      });
      if (onUpdateUser) onUpdateUser(updated);
      setProfSuccess('Profile settings successfully saved.');
      setTimeout(() => setProfSuccess(null), 3000);
    } catch (err: any) {
      alert(`Error saving profile: ${err.message}`);
    } finally {
      setProfSaving(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPassword || newPassword.length < 8) {
      alert('Password must be at least 8 characters long.');
      return;
    }
    try {
      const res = await api.changePassword({
        current_password: curPassword || undefined,
        new_password: newPassword,
      });
      setPwMsg(res.message);
      setCurPassword('');
      setNewPassword('');
      setTimeout(() => setPwMsg(null), 3000);
    } catch (err: any) {
      alert(`Password error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header matching Screen 13 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Security Settings
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Configure telemetry sensors, automated detection policies, and governance
          </p>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition self-start sm:self-auto"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{savedMsg ? 'Saved!' : 'Save Settings'}</span>
        </button>
      </div>

      {/* Tabs matching Screen 13 */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-semibold overflow-x-auto">
        <button
          onClick={() => setActiveTab('profile')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'profile'
              ? 'bg-sky-600 text-white font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <UserIcon className="w-3.5 h-3.5" />
          <span>Profile Settings</span>
        </button>
        <button
          onClick={() => setActiveTab('general')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap ${
            activeTab === 'general'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          General
        </button>
        <button
          onClick={() => setActiveTab('monitoring')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap ${
            activeTab === 'monitoring'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Monitoring
        </button>
        <button
          onClick={() => setActiveTab('notifications')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap ${
            activeTab === 'notifications'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Notifications
        </button>
        <button
          onClick={() => setActiveTab('integrations')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap ${
            activeTab === 'integrations'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Integrations
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`px-3 py-1.5 rounded-lg transition whitespace-nowrap ${
            activeTab === 'users'
              ? 'bg-sky-600 text-white'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          User Management
        </button>
      </div>

      {/* TAB 1: PROFILE SETTINGS */}
      {activeTab === 'profile' && (
        <div className="space-y-6">
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-xs space-y-6">
            <div className="flex flex-col sm:flex-row items-center gap-4 pb-5 border-b border-slate-100 dark:border-slate-800">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-sky-600 to-indigo-600 text-white flex items-center justify-center text-xl font-bold shadow-md shadow-sky-600/20">
                {(profName || 'Admin').split(' ').map((n) => n[0]).join('').slice(0, 2).toUpperCase()}
              </div>
              <div className="text-center sm:text-left flex-1">
                <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">{profName}</h3>
                  <span className="inline-block px-2 py-0.5 rounded-full text-[10px] font-bold bg-sky-100 dark:bg-sky-950 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800 self-center sm:self-auto">
                    {currentUser?.role || 'Super Admin'}
                  </span>
                </div>
                <p className="text-slate-500 dark:text-slate-400 font-mono text-[11px] mt-0.5">
                  {currentUser?.email || 'admin@cybershield.corp'}
                </p>
                <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-semibold mt-1">
                  Security Clearance: Tier-3 Unrestricted SOC Access
                </p>
              </div>
            </div>

            {profSuccess && (
              <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 rounded-lg flex items-center gap-2 text-xs">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>{profSuccess}</span>
              </div>
            )}

            <form onSubmit={handleSaveProfile} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    value={profName}
                    onChange={(e) => setProfName(e.target.value)}
                    required
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Corporate Email
                  </label>
                  <input
                    type="email"
                    value={currentUser?.email || 'admin@cybershield.corp'}
                    disabled
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-xs cursor-not-allowed"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Department / Unit
                  </label>
                  <select
                    value={profDept}
                    onChange={(e) => setProfDept(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  >
                    <option value="Executive Security Office">Executive Security Office</option>
                    <option value="Security Operations Center (SOC)">Security Operations Center (SOC)</option>
                    <option value="Cyber Threat Intelligence">Cyber Threat Intelligence</option>
                    <option value="SecOps & Identity Management">SecOps & Identity Management</option>
                    <option value="Incident Response Team">Incident Response Team</option>
                    <option value="Engineering & Dev">Engineering & Dev</option>
                    <option value="Finance & Procurement">Finance & Procurement</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Emergency Phone
                  </label>
                  <input
                    type="tel"
                    value={profPhone}
                    onChange={(e) => setProfPhone(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Operating Timezone
                  </label>
                  <select
                    value={profTimezone}
                    onChange={(e) => setProfTimezone(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  >
                    <option value="Asia/Kolkata (UTC+05:30)">Asia/Kolkata (UTC+05:30)</option>
                    <option value="UTC (UTC+00:00)">UTC (UTC+00:00 - GMT)</option>
                    <option value="America/New_York (UTC-05:00)">America/New_York (UTC-05:00 - EST)</option>
                    <option value="America/Los_Angeles (UTC-08:00)">America/Los_Angeles (UTC-08:00 - PST)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Operator ID
                  </label>
                  <input
                    type="text"
                    value="EMP-0001 (Master Operator)"
                    disabled
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-xs cursor-not-allowed"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={profSaving}
                  className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-xs transition disabled:opacity-50"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{profSaving ? 'Saving Profile...' : 'Save Profile Changes'}</span>
                </button>
              </div>
            </form>
          </div>

          {/* Password update section */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-xs space-y-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-sky-600" />
              <span>Password & Security Key</span>
            </h4>
            {pwMsg && (
              <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 rounded-lg text-xs">
                {pwMsg}
              </div>
            )}
            <form onSubmit={handleChangePassword} className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Current Password
                  </label>
                  <input
                    type="password"
                    placeholder="Enter existing password"
                    value={curPassword}
                    onChange={(e) => setCurPassword(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    New Password
                  </label>
                  <input
                    type="password"
                    placeholder="At least 8 characters"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-xs"
                  />
                </div>
              </div>
              <button
                type="submit"
                className="px-4 py-2 bg-slate-800 dark:bg-slate-700 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold"
              >
                Update Password
              </button>
            </form>
          </div>
        </div>
      )}

      {/* TAB 2: MONITORING CONTROLS */}
      {activeTab === 'monitoring' && (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-xs space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1">
              Core Monitoring Controls
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              Enable or tune live sensor telemetry pipelines across company endpoints and gateways.
            </p>

            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {/* Toggle 1: Monitor web activity */}
              <div className="py-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white">
                    Monitor web activity
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Inspect outbound URLs and enforce web gateway warning interstitials.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle('monitorWebActivity')}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition duration-200 ${
                    toggles.monitorWebActivity ? 'bg-sky-600 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>

              {/* Toggle 2: Scan email for phishing */}
              <div className="py-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white">
                    Scan email for phishing
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Execute TF-IDF NLP model on incoming email subjects and body text.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle('scanEmailPhishing')}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition duration-200 ${
                    toggles.scanEmailPhishing ? 'bg-sky-600 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>

              {/* Toggle 3: Detect sensitive data exposure */}
              <div className="py-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white">
                    Detect sensitive data exposure (DLP)
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Scan repositories and communications for leaked AWS keys, tokens, and credentials with UI masking.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle('detectSensitiveData')}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition duration-200 ${
                    toggles.detectSensitiveData ? 'bg-sky-600 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>

              {/* Toggle 4: Monitor file uploads */}
              <div className="py-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white">
                    Monitor file uploads
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Analyze byte Shannon entropy and Windows PE headers without execution.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle('monitorFileUploads')}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition duration-200 ${
                    toggles.monitorFileUploads ? 'bg-sky-600 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>

              {/* Toggle 5: Enable real-time alerts */}
              <div className="py-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white">
                    Enable real-time alerts
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Dispatch email and optional SMS warnings for Critical and High severity incidents with deduplication.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle('enableRealTimeAlerts')}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition duration-200 ${
                    toggles.enableRealTimeAlerts ? 'bg-sky-600 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>
            </div>
          </div>

          {/* Monitoring Policies Section matching Screen 13 */}
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Monitoring Policies
              </h4>
              <button
                onClick={() => alert('Editing Policy rules...')}
                className="px-3 py-1 text-xs font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 text-slate-700 dark:text-slate-300 rounded"
              >
                Edit Policy
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                <span className="font-semibold text-slate-900 dark:text-white block">Standard Policy</span>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">General workforce email & web gateway inspection.</p>
              </div>
              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                <span className="font-semibold text-slate-900 dark:text-white block">Strict (Executive & Finance)</span>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Enhanced DLP, SMS alerts, and zero-trust verification.</p>
              </div>
              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                <span className="font-semibold text-slate-900 dark:text-white block">DevOps & Cloud Admin</span>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Git commit scanning and cloud audit log correlation.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* OTHER TABS (GENERAL, NOTIFICATIONS, INTEGRATIONS, USERS) */}
      {activeTab === 'general' && (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">General Security Governance</h3>
          <p className="text-slate-500">Configure organization name, session inactivity timeouts, and SOC retention rules.</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div>
              <label className="block font-medium mb-1 text-slate-600 dark:text-slate-400">Organization Name</label>
              <input type="text" defaultValue="CYBERSHIELD AI Enterprise Global" className="w-full px-3 py-2 border rounded-lg border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800" />
            </div>
            <div>
              <label className="block font-medium mb-1 text-slate-600 dark:text-slate-400">Session Inactivity Lock</label>
              <select className="w-full px-3 py-2 border rounded-lg border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                <option>15 Minutes</option>
                <option>30 Minutes</option>
                <option>1 Hour</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'notifications' && (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Notification Endpoints</h3>
          <p className="text-slate-500">Manage Twilio SMS, AWS SES Email, and webhook gateways.</p>
          <div className="p-3 border rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 text-emerald-800 dark:text-emerald-300">
            Corporate Email Delivery: Verified (Exchange & Postfix Gateways Active)
          </div>
        </div>
      )}

      {activeTab === 'integrations' && (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Connected SIEM & Threat Intel</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 border rounded-lg bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 flex justify-between items-center">
              <span>Splunk / Elastic Connector</span>
              <span className="text-[10px] bg-emerald-100 text-emerald-800 font-bold px-2 py-0.5 rounded">CONNECTED</span>
            </div>
            <div className="p-3 border rounded-lg bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 flex justify-between items-center">
              <span>VirusTotal & AbuseIPDB Threat Feeds</span>
              <span className="text-[10px] bg-sky-100 text-sky-800 font-bold px-2 py-0.5 rounded">ACTIVE</span>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Role-Based Access Control (RBAC) Matrix</h3>
          <p className="text-slate-500">4 Enforced Tiers: Super Admin, Security Administrator, SOC Analyst, Employee.</p>
        </div>
      )}
    </div>
  );
};
