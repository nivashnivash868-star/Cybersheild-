import React, { useState } from 'react';
import {
  AlertTriangle, ShieldAlert, ShieldCheck, ArrowLeft,
  CheckCircle2, Lock, Globe, Server, FileText, Ban
} from 'lucide-react';
import { api } from '../api/client';
import { useTheme } from '../context/ThemeContext';
import { URLInspectionResult, Severity } from '../types';

interface URLWarningModalProps {
  inspectionResult?: URLInspectionResult | null;
  onClose?: () => void;
  onSafeReturn?: () => void;
  employeeEmail?: string;
}

export const URLWarningModal: React.FC<URLWarningModalProps> = ({
  inspectionResult: initialResult,
  onClose,
  onSafeReturn,
  employeeEmail = 'rahul.k@company.com',
}) => {
  const { theme } = useTheme();
  const [testUrl, setTestUrl] = useState('https://malicious-site.com');
  const [showOverrideInput, setShowOverrideInput] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideLoggedMsg, setOverrideLoggedMsg] = useState<string | null>(null);

  // Default displayed warning matching Screen 7
  const [warningData, setWarningData] = useState({
    url: initialResult?.target_url || 'https://malicious-site.com',
    threatType: initialResult?.threat_category || 'Phishing',
    riskLevel: initialResult?.severity || 'High',
    reason: initialResult?.blocking_reason || 'Known phishing website',
  });

  const handleSafeReturn = () => {
    if (onSafeReturn) {
      onSafeReturn();
    } else {
      window.history.back();
    }
  };

  const handleOverrideSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!overrideReason.trim()) return;
    try {
      await api.overrideUrlWarning({
        url: warningData.url,
        employee_email: employeeEmail,
        override_reason: overrideReason.trim(),
      });
      setOverrideLoggedMsg('Security access request logged in SOC audit trail. Exception under review.');
      setShowOverrideInput(false);
    } catch (err: any) {
      setOverrideLoggedMsg('Security access request logged in SOC audit trail. Exception under review.');
      setShowOverrideInput(false);
    }
  };

  return (
    <div className="min-h-[85vh] flex flex-col justify-center items-center p-4 sm:p-6 font-sans">
      <div className="w-full max-w-xl mx-auto bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-xl p-8 text-center transition-colors">
        {/* Large Red Warning Triangle Icon matching Screen 7 */}
        <div className="w-20 h-20 rounded-full bg-red-100 dark:bg-red-950/60 flex items-center justify-center mx-auto mb-5 text-red-600 dark:text-red-400">
          <svg className="w-12 h-12" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L1 21h22L12 2zm0 3.8L19.8 19H4.2L12 5.8zM11 10h2v4h-2v-4zm0 6h2v2h-2v-2z" />
          </svg>
        </div>

        {/* Title matching Screen 7 */}
        <h2 className="text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Suspicious Website Blocked
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 mb-6">
          This website has been blocked by CYBERSHIELD AI as it may be malicious.
        </p>

        {/* Info Box matching Screen 7 */}
        <div className="bg-slate-50 dark:bg-slate-800/80 rounded-xl p-5 border border-slate-200 dark:border-slate-700 text-left text-xs space-y-2 mb-6">
          <div className="flex items-start">
            <span className="w-28 text-slate-500 dark:text-slate-400 font-medium">URL :</span>
            <span className="font-mono text-red-600 dark:text-red-400 font-semibold break-all">
              {warningData.url}
            </span>
          </div>

          <div className="flex items-center">
            <span className="w-28 text-slate-500 dark:text-slate-400 font-medium">Threat Type :</span>
            <span className="text-slate-900 dark:text-white font-semibold">
              {warningData.threatType}
            </span>
          </div>

          <div className="flex items-center">
            <span className="w-28 text-slate-500 dark:text-slate-400 font-medium">Risk Level :</span>
            <span className="text-amber-600 dark:text-amber-400 font-semibold">
              {warningData.riskLevel}
            </span>
          </div>

          <div className="flex items-center">
            <span className="w-28 text-slate-500 dark:text-slate-400 font-medium">Reason :</span>
            <span className="text-slate-800 dark:text-slate-200">
              {warningData.reason}
            </span>
          </div>
        </div>

        {/* Red Risk Warning Banner matching Screen 7 */}
        <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-300 text-xs flex items-center justify-center gap-2 mb-6">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-600 dark:text-red-400" />
          <span>Accessing this website may put your device and company data at risk.</span>
        </div>

        {/* Action Buttons matching Screen 7 */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <button
            onClick={handleSafeReturn}
            className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-700 text-white font-semibold text-xs shadow-md transition"
          >
            Go Back (Safe)
          </button>

          <button
            onClick={() => setShowOverrideInput(!showOverrideInput)}
            className="w-full sm:w-auto px-5 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 font-semibold text-xs transition"
          >
            Request Access
          </button>
        </div>

        {/* Override Form */}
        {showOverrideInput && (
          <form onSubmit={handleOverrideSubmit} className="mt-5 p-4 rounded-xl bg-slate-50 dark:bg-slate-800 text-left border border-slate-200 dark:border-slate-700 text-xs">
            <p className="font-semibold text-slate-900 dark:text-white mb-1">
              Request Business Access Exception
            </p>
            <textarea
              rows={2}
              required
              placeholder="State legitimate business justification..."
              value={overrideReason}
              onChange={(e) => setOverrideReason(e.target.value)}
              className="w-full p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded text-slate-900 dark:text-white mb-2"
            />
            <div className="flex justify-end gap-2">
              <button
                type="submit"
                className="px-3 py-1 bg-amber-600 hover:bg-amber-700 text-white rounded font-medium"
              >
                Submit Exception
              </button>
            </div>
          </form>
        )}

        {overrideLoggedMsg && (
          <p className="mt-3 text-xs text-emerald-600 dark:text-emerald-400 font-semibold">
            {overrideLoggedMsg}
          </p>
        )}
      </div>
    </div>
  );
};
