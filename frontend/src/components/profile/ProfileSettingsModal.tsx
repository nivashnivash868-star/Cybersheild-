import React, { useState } from 'react';
import {
  User, ShieldCheck, Mail, Phone, Building2, Globe, Clock,
  Lock, KeyRound, Smartphone, Bell, Eye, EyeOff, Save, X,
  CheckCircle2, AlertTriangle, Copy, Check, RefreshCw, ShieldAlert,
  Fingerprint
} from 'lucide-react';
import { UserSession } from '../../types';
import { api } from '../../api/client';
import { useTheme } from '../../context/ThemeContext';

interface ProfileSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: UserSession;
  onUpdateUser: (updatedUser: UserSession) => void;
}

export const ProfileSettingsModal: React.FC<ProfileSettingsModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onUpdateUser,
}) => {
  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'notifications' | 'api'>('general');

  // General profile state
  const [fullName, setFullName] = useState(currentUser.name || '');
  const [department, setDepartment] = useState(currentUser.department || 'Executive Security Office');
  const [phone, setPhone] = useState('+1 (555) 942-8321');
  const [timezone, setTimezone] = useState('Asia/Kolkata (UTC+05:30)');
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [profileSuccessMsg, setProfileSuccessMsg] = useState<string | null>(null);
  const [profileErrorMsg, setProfileErrorMsg] = useState<string | null>(null);

  // Security / Password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [passwordSuccessMsg, setPasswordSuccessMsg] = useState<string | null>(null);
  const [passwordErrorMsg, setPasswordErrorMsg] = useState<string | null>(null);

  // 2FA state
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(true);
  const [show2FASetup, setShow2FASetup] = useState(false);

  // Notification toggles
  const [notifications, setNotifications] = useState({
    criticalIncidentEmail: true,
    dlpLeakSms: true,
    browserPushAlerts: true,
    dailySocDigest: false,
    weeklyReportEmail: true,
  });

  // API Token state
  const [copiedToken, setCopiedToken] = useState(false);
  const [apiToken, setApiToken] = useState('cs_live_9f82a17cb6e34891b012d4a7e93c5fa8');
  const [tokenRotatedMsg, setTokenRotatedMsg] = useState(false);

  if (!isOpen) return null;

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingProfile(true);
    setProfileSuccessMsg(null);
    setProfileErrorMsg(null);

    try {
      const updated = await api.updateProfile({
        full_name: fullName.trim(),
        department: department.trim(),
        phone_number: phone.trim(),
      });
      onUpdateUser(updated);
      setProfileSuccessMsg('Profile settings updated successfully.');
      setTimeout(() => setProfileSuccessMsg(null), 3000);
    } catch (err: any) {
      setProfileErrorMsg(err.message || 'Failed to update profile settings.');
    } finally {
      setIsSavingProfile(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPassword) {
      setPasswordErrorMsg('Please enter a new password.');
      return;
    }
    if (!currentPassword || newPassword.length < 12) {
      setPasswordErrorMsg('Password must be at least 8 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordErrorMsg('New password and confirmation do not match.');
      return;
    }

    setIsChangingPassword(true);
    setPasswordSuccessMsg(null);
    setPasswordErrorMsg(null);

    try {
      const res = await api.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPasswordSuccessMsg(res.message || 'Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setPasswordSuccessMsg(null), 3000);
    } catch (err: any) {
      setPasswordErrorMsg(err.message || 'Failed to change password.');
    } finally {
      setIsChangingPassword(false);
    }
  };

  const handleRotateToken = () => {
    const chars = 'abcdef0123456789';
    let newToken = 'cs_live_';
    for (let i = 0; i < 32; i++) {
      newToken += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setApiToken(newToken);
    setTokenRotatedMsg(true);
    setTimeout(() => setTokenRotatedMsg(false), 2500);
  };

  const handleCopyToken = () => {
    navigator.clipboard.writeText(apiToken);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const getInitials = (name?: string) => {
    if (!name) return 'A';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .slice(0, 2)
      .toUpperCase();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-xs flex items-center justify-center p-3 sm:p-6 overflow-y-auto animate-in fade-in duration-150">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/60 dark:bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-sky-600 text-white flex items-center justify-center shadow-md shadow-sky-600/30">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                User Profile & Account Settings
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Manage personal credentials, role permissions, and SOC notification preferences
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 sm:gap-2 px-6 pt-3 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-semibold overflow-x-auto">
          <button
            onClick={() => setActiveTab('general')}
            className={`flex items-center gap-2 px-3 py-2 border-b-2 transition whitespace-nowrap ${
              activeTab === 'general'
                ? 'border-sky-600 text-sky-600 dark:text-sky-400 font-bold'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <User className="w-3.5 h-3.5" />
            <span>Profile Details</span>
          </button>
          <button
            onClick={() => setActiveTab('security')}
            className={`flex items-center gap-2 px-3 py-2 border-b-2 transition whitespace-nowrap ${
              activeTab === 'security'
                ? 'border-sky-600 text-sky-600 dark:text-sky-400 font-bold'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Password & 2FA</span>
          </button>
          <button
            onClick={() => setActiveTab('notifications')}
            className={`flex items-center gap-2 px-3 py-2 border-b-2 transition whitespace-nowrap ${
              activeTab === 'notifications'
                ? 'border-sky-600 text-sky-600 dark:text-sky-400 font-bold'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Bell className="w-3.5 h-3.5" />
            <span>Notification Rules</span>
          </button>
          <button
            onClick={() => setActiveTab('api')}
            className={`flex items-center gap-2 px-3 py-2 border-b-2 transition whitespace-nowrap ${
              activeTab === 'api'
                ? 'border-sky-600 text-sky-600 dark:text-sky-400 font-bold'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>API & Keys</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 p-6 overflow-y-auto space-y-6 text-xs text-slate-700 dark:text-slate-300">
          {/* TAB 1: GENERAL PROFILE */}
          {activeTab === 'general' && (
            <form onSubmit={handleSaveProfile} className="space-y-6">
              {/* Profile Card Banner */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 flex flex-col sm:flex-row items-center gap-4">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-sky-600 to-indigo-600 text-white flex items-center justify-center text-xl font-bold shadow-md shadow-sky-600/20 ring-4 ring-white dark:ring-slate-900">
                  {getInitials(fullName)}
                </div>
                <div className="flex-1 text-center sm:text-left">
                  <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 dark:text-white">{fullName}</h3>
                    <span className="inline-block px-2 py-0.5 rounded-full text-[10px] font-bold bg-sky-100 dark:bg-sky-950 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800 self-center sm:self-auto">
                      {currentUser.role}
                    </span>
                  </div>
                  <p className="text-slate-500 dark:text-slate-400 font-mono text-[11px] mt-0.5">
                    {currentUser.email}
                  </p>
                  <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-semibold mt-1 flex items-center justify-center sm:justify-start gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    Security Clearance: Tier-3 Unrestricted SOC Access
                  </p>
                </div>
              </div>

              {profileSuccessMsg && (
                <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 rounded-lg flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>{profileSuccessMsg}</span>
                </div>
              )}

              {profileErrorMsg && (
                <div className="p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-300 rounded-lg flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                  <span>{profileErrorMsg}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    required
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Corporate Email (Managed by IdP)
                  </label>
                  <input
                    type="email"
                    value={currentUser.email}
                    disabled
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-xs cursor-not-allowed"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Department / Security Unit
                  </label>
                  <select
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  >
                    <option value="Executive Security Office">Executive Security Office</option>
                    <option value="Security Operations Center (SOC)">Security Operations Center (SOC)</option>
                    <option value="Cyber Threat Intelligence">Cyber Threat Intelligence</option>
                    <option value="SecOps & Identity Management">SecOps & Identity Management</option>
                    <option value="Incident Response Team">Incident Response Team</option>
                    <option value="DevOps & Cloud Security">DevOps & Cloud Security</option>
                    <option value="Engineering & Dev">Engineering & Dev</option>
                    <option value="Finance & Procurement">Finance & Procurement</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Emergency Security Mobile
                  </label>
                  <input
                    type="tel"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  />
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Operating Timezone
                  </label>
                  <select
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                  >
                    <option value="Asia/Kolkata (UTC+05:30)">Asia/Kolkata (UTC+05:30)</option>
                    <option value="UTC (UTC+00:00)">UTC (UTC+00:00 - Universal Coordinated Time)</option>
                    <option value="America/New_York (UTC-05:00)">America/New_York (UTC-05:00 - Eastern Time)</option>
                    <option value="America/Los_Angeles (UTC-08:00)">America/Los_Angeles (UTC-08:00 - Pacific Time)</option>
                    <option value="Europe/London (UTC+00:00)">Europe/London (UTC+00:00 - GMT)</option>
                    <option value="Europe/Frankfurt (UTC+01:00)">Europe/Frankfurt (UTC+01:00 - CET)</option>
                    <option value="Asia/Singapore (UTC+08:00)">Asia/Singapore (UTC+08:00 - SGT)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                    Assigned Employee ID
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
                  disabled={isSavingProfile}
                  className="flex items-center gap-2 px-5 py-2.5 bg-sky-600 hover:bg-sky-700 text-white rounded-lg text-xs font-semibold shadow-md transition disabled:opacity-50"
                >
                  {isSavingProfile ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Saving Profile...</span>
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4" />
                      <span>Save Changes</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          )}

          {/* TAB 2: PASSWORD & 2FA */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              {/* Change Password Card */}
              <div className="p-4 sm:p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 shadow-xs">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                  <span>Update Account Password</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Enforce strong credentials adhering to corporate security guidelines (minimum 8 characters, numbers & symbols).
                </p>

                {passwordSuccessMsg && (
                  <div className="mb-4 p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 rounded-lg flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>{passwordSuccessMsg}</span>
                  </div>
                )}

                {passwordErrorMsg && (
                  <div className="mb-4 p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-300 rounded-lg flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                    <span>{passwordErrorMsg}</span>
                  </div>
                )}

                <form onSubmit={handleChangePassword} className="space-y-4">
                  <div>
                    <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                      Current Password
                    </label>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="Enter existing password"
                      className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                        New Password
                      </label>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="At least 8 characters"
                        required
                        className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                      />
                    </div>

                    <div>
                      <label className="block text-slate-600 dark:text-slate-400 font-medium mb-1">
                        Confirm New Password
                      </label>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Re-type new password"
                        required
                        className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-sky-500 outline-none text-xs"
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={showPassword}
                        onChange={(e) => setShowPassword(e.target.checked)}
                        className="rounded text-sky-600 focus:ring-sky-500 border-slate-300 dark:border-slate-600 w-3.5 h-3.5"
                      />
                      <span className="text-slate-600 dark:text-slate-400">Show password characters</span>
                    </label>

                    <button
                      type="submit"
                      disabled={isChangingPassword}
                      className="px-4 py-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg font-semibold text-xs transition shadow-xs disabled:opacity-50"
                    >
                      {isChangingPassword ? 'Updating Password...' : 'Update Password'}
                    </button>
                  </div>
                </form>
              </div>

              {/* 2FA Card */}
              <div className="p-4 sm:p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 shadow-xs">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="p-2.5 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400 border border-purple-200 dark:border-purple-800">
                      <Smartphone className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        Two-Factor Authentication (2FA / TOTP)
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300">
                          {twoFactorEnabled ? 'Active' : 'Disabled'}
                        </span>
                      </h4>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-lg">
                        Requires a 6-digit TOTP verification code from your authenticator app (Google Authenticator, Microsoft Authenticator, or 1Password) upon login.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => setTwoFactorEnabled(!twoFactorEnabled)}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      twoFactorEnabled ? 'bg-sky-600' : 'bg-slate-200 dark:bg-slate-700'
                    }`}
                  >
                    <span
                      className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm ring-0 transition duration-200 ease-in-out ${
                        twoFactorEnabled ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>

                {twoFactorEnabled && (
                  <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
                    <span className="text-slate-500 dark:text-slate-400">
                      Configured Method: <strong className="text-slate-900 dark:text-slate-200">Hardware & TOTP Authenticator</strong>
                    </span>
                    <button
                      onClick={() => setShow2FASetup(!show2FASetup)}
                      className="text-sky-600 dark:text-sky-400 font-semibold hover:underline"
                    >
                      {show2FASetup ? 'Hide QR Code' : 'View Authenticator Secret Key'}
                    </button>
                  </div>
                )}

                {show2FASetup && (
                  <div className="mt-3 p-4 bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3">
                    <p className="font-semibold text-slate-800 dark:text-slate-200">
                      Scan QR code or manually enter the Base32 security key:
                    </p>
                    <div className="flex items-center gap-4">
                      <div className="w-24 h-24 bg-white p-2 rounded-lg border border-slate-200 dark:border-slate-700 flex items-center justify-center">
                        <Fingerprint className="w-16 h-16 text-sky-600" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-[11px] text-slate-500">Security Key:</p>
                        <code className="px-2 py-1 bg-slate-200 dark:bg-slate-800 rounded text-sky-600 dark:text-sky-400 font-mono text-xs font-bold">
                          JBSWY3DPEHPK3PXP
                        </code>
                        <p className="text-[10px] text-slate-400">Issuer: CYBERSHIELD Enterprise SOC</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: NOTIFICATIONS */}
          {activeTab === 'notifications' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1">
                  Automated Security Alerts & Channels
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Select which security events automatically trigger notifications to your verified endpoints.
                </p>

                <div className="space-y-3">
                  {[
                    {
                      key: 'criticalIncidentEmail',
                      title: 'Critical Threat & Incident Emails',
                      desc: 'Instant dispatch when a Critical severity incident is detected by correlation engine.',
                    },
                    {
                      key: 'dlpLeakSms',
                      title: 'Data Loss (DLP) Secret Exposure SMS Alerts',
                      desc: 'Urgent mobile notification for leaked corporate credentials, API keys, and database tokens.',
                    },
                    {
                      key: 'browserPushAlerts',
                      title: 'Real-Time Browser In-App Banners',
                      desc: 'Flash alerts in the SOC workspace when new anomaly events arrive.',
                    },
                    {
                      key: 'dailySocDigest',
                      title: 'Daily 08:00 AM SOC Digest Summary',
                      desc: 'Consolidated briefing covering 24/7 telemetry feeds, active investigations, and employee risk scores.',
                    },
                    {
                      key: 'weeklyReportEmail',
                      title: 'Weekly Threat Trend Analytics PDF',
                      desc: 'Aggregated analytics covering phishing detection, malware volume, and DLP audit trails.',
                    },
                  ].map((item) => (
                    <div
                      key={item.key}
                      className="flex items-center justify-between p-3 rounded-lg border border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition"
                    >
                      <div className="pr-4">
                        <p className="font-semibold text-slate-800 dark:text-slate-200">{item.title}</p>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">{item.desc}</p>
                      </div>
                      <button
                        onClick={() =>
                          setNotifications((prev: any) => ({ ...prev, [item.key]: !prev[item.key] }))
                        }
                        className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          (notifications as any)[item.key] ? 'bg-sky-600' : 'bg-slate-200 dark:bg-slate-700'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-0 transition duration-200 ease-in-out ${
                            (notifications as any)[item.key] ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: API & KEYS */}
          {activeTab === 'api' && (
            <div className="space-y-4">
              <div className="p-4 sm:p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                    <span>Personal SOC Operator API Key</span>
                  </h3>
                  <button
                    onClick={handleRotateToken}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-700 rounded-md text-[11px] transition"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Regenerate Key</span>
                  </button>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Use this token to authenticate external SIEM connectors, CLI scripts, and webhooks against CYBERSHIELD AI REST endpoints.
                </p>

                {tokenRotatedMsg && (
                  <div className="mb-3 p-2.5 bg-purple-50 dark:bg-purple-950/60 border border-purple-200 dark:border-purple-800 text-purple-700 dark:text-purple-300 rounded-lg text-xs">
                    New API access token generated. Remember to update your active automation scripts!
                  </div>
                )}

                <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950">
                  <code className="flex-1 font-mono text-xs text-sky-600 dark:text-sky-400 break-all select-all">
                    {apiToken}
                  </code>
                  <button
                    onClick={handleCopyToken}
                    className="flex items-center gap-1 px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 rounded text-slate-700 dark:text-slate-300 font-medium transition text-xs shrink-0"
                  >
                    {copiedToken ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="mt-4 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60 text-amber-800 dark:text-amber-300 text-[11px] flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>
                    Keep your API tokens confidential. CYBERSHIELD DLP automated scanners monitor public repositories and will instantly revoke exposed credentials.
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/60 dark:bg-slate-950/40">
          <span className="text-[11px] text-slate-400">
            Account ID: #{currentUser.id} • Authenticated Session
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 font-semibold text-xs transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
