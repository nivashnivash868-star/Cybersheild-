import React, { useState, useEffect } from 'react';
import {
  Mail, Globe, MessageSquare, AlertTriangle, ShieldCheck,
  Send, Sparkles, CheckCircle2, Copy, Check, Info, ShieldAlert
} from 'lucide-react';
import { api } from '../api/client';
import { PhishingAnalysisResult } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface PhishingPageProps {
  initialSubmissionType?: 'url' | 'email' | 'sms';
}

export const PhishingPage: React.FC<PhishingPageProps> = ({ initialSubmissionType = 'url' }) => {
  const [submissionType, setSubmissionType] = useState<'url' | 'email' | 'sms'>(initialSubmissionType);
  const [content, setContent] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [senderInfo, setSenderInfo] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PhishingAnalysisResult | null>(null);

  const [samples, setSamples] = useState<any[]>([]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (initialSubmissionType) {
      setSubmissionType(initialSubmissionType);
    }
  }, [initialSubmissionType]);

  useEffect(() => {
    api.getPhishingSamples().then(setSamples).catch(console.error);
  }, []);

  const handleSelectSample = (sample: any) => {
    setSubmissionType(sample.submission_type);
    setContent(sample.content);
    setEmailSubject(sample.email_subject || '');
    setSenderInfo(sample.sender_info || '');
    setError(null);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      setError('Please provide a URL or message content to inspect.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.analyzePhishing({
        submission_type: submissionType,
        content: content.trim(),
        email_subject: emailSubject.trim() || undefined,
        sender_info: senderInfo.trim() || undefined,
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Check input safety standards.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyHash = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.analysis_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="pb-2 border-b border-slate-200">
        <h1 className="text-xl font-bold tracking-tight text-slate-900">Phishing & Scam Detection Engine</h1>
        <p className="text-xs text-slate-500">
          Static URL feature vectorization, SSRF protection filters, and Scikit-Learn TF-IDF NLP classification
        </p>
      </div>

      {/* Preset Test Scenarios Selector */}
      <div className="bg-sky-50 border border-sky-200 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles className="w-4 h-4 text-sky-700" />
          <h3 className="text-xs font-semibold text-sky-900 uppercase tracking-wider">
            Quick-Load Synthetic SOC Scenarios
          </h3>
        </div>
        <p className="text-xs text-sky-800 mb-3">
          Select pre-engineered attack vectors to test detection models and explainability engines instantly:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {samples.map((s) => (
            <button
              key={s.id}
              onClick={() => handleSelectSample(s)}
              className="text-left p-2.5 rounded-md bg-white border border-sky-200 hover:border-sky-400 hover:shadow-xs transition text-xs"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-slate-900 text-[11px] truncate">{s.title}</span>
                <span
                  className={`text-[9px] uppercase font-bold px-1 rounded ${
                    s.expected_risk === 'Critical'
                      ? 'bg-red-100 text-red-700'
                      : s.expected_risk === 'High'
                      ? 'bg-orange-100 text-orange-700'
                      : 'bg-emerald-100 text-emerald-700'
                  }`}
                >
                  {s.expected_risk}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 line-clamp-2">{s.description}</p>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Form: Input Controls */}
        <div className="lg:col-span-5 bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-4">
          <h3 className="text-sm font-semibold text-slate-900 pb-2 border-b border-slate-100">
            Submission Parameters
          </h3>

          {/* Type Selector Tabs */}
          <div className="grid grid-cols-3 gap-1 bg-slate-100 p-1 rounded-lg text-xs font-medium">
            <button
              type="button"
              onClick={() => setSubmissionType('url')}
              className={`py-1.5 rounded flex items-center justify-center gap-1.5 transition ${
                submissionType === 'url' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>URL</span>
            </button>
            <button
              type="button"
              onClick={() => setSubmissionType('email')}
              className={`py-1.5 rounded flex items-center justify-center gap-1.5 transition ${
                submissionType === 'email' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Email</span>
            </button>
            <button
              type="button"
              onClick={() => setSubmissionType('sms')}
              className={`py-1.5 rounded flex items-center justify-center gap-1.5 transition ${
                submissionType === 'sms' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>SMS / Chat</span>
            </button>
          </div>

          <form onSubmit={handleAnalyze} className="space-y-3">
            {submissionType === 'email' && (
              <>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 uppercase mb-1">
                    Email Subject Line
                  </label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="e.g. URGENT: Action required on your account"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 uppercase mb-1">
                    Sender Information (Email or Display Name)
                  </label>
                  <input
                    type="text"
                    value={senderInfo}
                    onChange={(e) => setSenderInfo(e.target.value)}
                    placeholder="e.g. security-team@microsoft-verify.xyz"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </div>
              </>
            )}

            {submissionType === 'sms' && (
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 uppercase mb-1">
                  Sender Phone / Shortcode
                </label>
                <input
                  type="text"
                  value={senderInfo}
                  onChange={(e) => setSenderInfo(e.target.value)}
                  placeholder="e.g. +1 (888) 555-0199 or 38491"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              </div>
            )}

            <div>
              <label className="block text-[11px] font-semibold text-slate-600 uppercase mb-1">
                {submissionType === 'url' ? 'Suspicious URL to Inspect' : 'Message Body Content'}
              </label>
              {submissionType === 'url' ? (
                <input
                  type="text"
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="http://login-microsoft365-verify.xyz/auth..."
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              ) : (
                <textarea
                  rows={6}
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Paste raw email or SMS body text here for NLP classification..."
                  className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-sky-500 font-mono"
                />
              )}
            </div>

            {/* SSRF Guard Note */}
            <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-[11px] text-slate-600 flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600 mt-0.5 shrink-0" />
              <span>
                <strong>SSRF Protection Enforced:</strong> Private IP ranges (RFC 1918), loopback, link-local, and cloud metadata queries are blocked from outbound resolution. Content is inspected statically without execution.
              </span>
            </div>

            {error && (
              <div className="p-3 bg-red-50 text-red-800 border border-red-200 rounded-lg text-xs">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-sky-600 text-white font-medium text-xs hover:bg-sky-700 transition flex items-center justify-center gap-2 shadow-xs disabled:opacity-50"
            >
              {loading ? (
                <span>Analyzing Features & Scoring Models...</span>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Execute Heuristic & NLP Analysis</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Panel: Analysis Results */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-5">
              {/* Result Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200 gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={result.risk_category} size="lg" />
                    <h3 className="text-base font-bold text-slate-900">
                      Threat Risk Score: {result.risk_score} / 100
                    </h3>
                  </div>
                  <p className="text-xs text-slate-500 mt-1 font-mono break-all">
                    Target: {result.target}
                  </p>
                </div>

                <button
                  onClick={handleCopyHash}
                  className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-800 font-mono px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 transition"
                  title="Copy analysis ID"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{result.analysis_id}</span>
                </button>
              </div>

              {/* Score Meter */}
              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-slate-700">Calibrated Risk Index</span>
                  <span className="font-mono text-slate-500">{result.risk_score}% Severity</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden">
                  <div
                    className={`h-2.5 rounded-full transition-all duration-500 ${
                      result.risk_score >= 80
                        ? 'bg-red-500'
                        : result.risk_score >= 60
                        ? 'bg-orange-500'
                        : result.risk_score >= 35
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${result.risk_score}%` }}
                  />
                </div>
              </div>

              {/* Explainable Classification Narrative */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-sky-600" />
                  <span>Explainable Classification Narrative</span>
                </h4>
                <p className="text-xs text-slate-700 leading-relaxed">{result.explanation}</p>
                <div className="mt-2 text-[10px] text-slate-500 font-mono border-t border-slate-200 pt-1.5">
                  Engine: {result.detection_engine} | {result.reputation_status}
                </div>
              </div>

              {/* Detected Suspicious Indicators */}
              <div>
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-2">
                  Detected Threat Signals & Weighted Indicators ({result.indicators.length})
                </h4>
                <div className="space-y-2">
                  {result.indicators.map((ind, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg border border-slate-200 bg-white flex items-start justify-between gap-3 text-xs"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-900">{ind.signal}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-600">
                            {ind.category}
                          </span>
                        </div>
                        <p className="text-slate-600 text-[11px]">{ind.description}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="text-[11px] font-bold text-red-600 font-mono">
                          +{ind.weight}
                        </span>
                        <div className="mt-0.5">
                          <SeverityBadge severity={ind.severity} size="sm" />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Precautions */}
              <div>
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-2">
                  Recommended Incident Precautions & Actions
                </h4>
                <div className="space-y-1.5">
                  {result.recommended_precautions.map((prec, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded-lg bg-sky-50 text-sky-950 border border-sky-100 text-xs flex items-start gap-2"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-sky-600 mt-0.5 shrink-0" />
                      <span>{prec}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full min-h-[420px] bg-slate-50 rounded-lg border border-dashed border-slate-300 p-8 flex flex-col items-center justify-center text-center">
              <div className="w-12 h-12 rounded-full bg-slate-200 flex items-center justify-center text-slate-500 mb-3">
                <Globe className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-semibold text-slate-700">Awaiting Inspection Input</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select a preset scenario above or enter a suspicious URL, email, or SMS to run the explainable detection engine.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
