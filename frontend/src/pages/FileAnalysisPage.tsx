import React, { useState, useEffect } from 'react';
import {
  Upload, FileSearch, Copy, Check,
  Sparkles, Binary, Lock
} from 'lucide-react';
import { api } from '../api/client';
import { FileAnalysisResult } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const FileAnalysisPage: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [samples, setSamples] = useState<any[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    api.getFileSamples().then(setSamples).catch(console.error);
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a local file to analyze.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.analyzeFile(file);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'File analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunSample = async (sampleId: string) => {
    setLoading(true);
    setError(null);
    setFile(null);
    try {
      const res = await api.analyzeSampleFile(sampleId);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Sample analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-200">
        <h1 className="text-xl font-bold tracking-tight text-slate-900">Suspicious File Analysis & Static Inspection</h1>
        <p className="text-xs text-slate-500">
          Cryptographic hash derivation, Shannon byte entropy, PE structure validation, and non-executing string scanning
        </p>
      </div>

      {/* Preset Synthetic Malware Artifacts */}
      <div className="bg-sky-50 border border-sky-200 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles className="w-4 h-4 text-sky-700" />
          <h3 className="text-xs font-semibold text-sky-900 uppercase tracking-wider">
            Preset Test Artifacts (Instant 1-Click Inspection)
          </h3>
        </div>
        <p className="text-xs text-sky-800 mb-3">
          Simulate file triage without handling live danger artifacts on your local filesystem:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {samples.map((s) => (
            <button
              key={s.id}
              onClick={() => handleRunSample(s.id)}
              className="text-left p-2.5 rounded-md bg-white border border-sky-200 hover:border-sky-400 hover:shadow-xs transition text-xs"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-slate-900 text-[11px] truncate">{s.name}</span>
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
        {/* Upload Form */}
        <div className="lg:col-span-5 bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-4">
          <h3 className="text-sm font-semibold text-slate-900 pb-2 border-b border-slate-100">
            Artifact Upload Sandbox
          </h3>

          <form onSubmit={handleUploadSubmit} className="space-y-4">
            <div className="border-2 border-dashed border-slate-300 rounded-lg p-6 text-center hover:bg-slate-50 transition cursor-pointer relative">
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
              />
              <div className="flex flex-col items-center">
                <Upload className="w-8 h-8 text-sky-600 mb-2" />
                <p className="text-xs font-semibold text-slate-700">
                  {file ? file.name : 'Choose file or drag & drop here'}
                </p>
                <p className="text-[11px] text-slate-500 mt-1">
                  Supported: Executables, Scripts, Documents, Binaries (Max 15MB)
                </p>
                {file && (
                  <span className="mt-2 text-[10px] px-2 py-0.5 rounded bg-sky-100 text-sky-800 font-mono">
                    Size: {roundBytes(file.size)}
                  </span>
                )}
              </div>
            </div>

            {/* Non-Execution Guarantee Notice */}
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-600 space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-slate-800">
                <Lock className="w-3.5 h-3.5 text-slate-600" />
                <span>Non-Execution Airgap Guarantee</span>
              </div>
              <p>
                Artifacts are analyzed through pure static memory stream inspection. Uploaded files are NEVER executed, invoked in shell, or exposed via public URL endpoints.
              </p>
            </div>

            {error && (
              <div className="p-3 bg-red-50 text-red-800 border border-red-200 rounded-lg text-xs">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !file}
              className="w-full py-2.5 rounded-lg bg-sky-600 text-white font-medium text-xs hover:bg-sky-700 transition flex items-center justify-center gap-2 shadow-xs disabled:opacity-50"
            >
              {loading ? (
                <span>Calculating Entropy & Scanning Signatures...</span>
              ) : (
                <>
                  <FileSearch className="w-3.5 h-3.5" />
                  <span>Execute Static Analysis</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs space-y-5">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200 gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={result.risk_category} size="lg" />
                    <h3 className="text-base font-bold text-slate-900">
                      Static Risk Score: {result.risk_score} / 100
                    </h3>
                  </div>
                  <p className="text-xs text-slate-600 mt-1 font-mono">
                    Artifact: {result.filename} ({roundBytes(result.filesize_bytes)})
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">MIME Type</span>
                  <span className="text-xs font-mono text-slate-800">{result.mime_type}</span>
                </div>
              </div>

              {/* Shannon Byte Entropy Gauge */}
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="font-semibold text-slate-800 flex items-center gap-1.5">
                    <Binary className="w-4 h-4 text-sky-600" />
                    <span>Shannon Byte Entropy: {result.entropy} / 8.000</span>
                  </span>
                  <span
                    className={`font-semibold text-[11px] ${
                      result.entropy >= 7.2 ? 'text-red-600' : 'text-emerald-700'
                    }`}
                  >
                    {result.entropy >= 7.2
                      ? 'Elevated (Likely Packed / Encrypted)'
                      : 'Nominal (Plaintext / Low Compression)'}
                  </span>
                </div>
                <div className="w-full bg-slate-200 rounded-full h-2.5 overflow-hidden">
                  <div
                    className={`h-2.5 rounded-full transition-all duration-500 ${
                      result.entropy >= 7.2
                        ? 'bg-red-500'
                        : result.entropy >= 6.5
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${(result.entropy / 8.0) * 100}%` }}
                  />
                </div>
                <p className="mt-2 text-[10px] text-slate-500">
                  Values &gt; 7.2 indicate high randomness, typical of obfuscated loaders, cryptographic payloads, or packers.
                </p>
              </div>

              {/* Cryptographic Hashes */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                  Cryptographic Hashes
                </h4>

                <div className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-center justify-between text-xs font-mono">
                  <div className="truncate mr-2">
                    <span className="text-slate-400 font-sans mr-2 text-[10px] uppercase font-bold">SHA-256:</span>
                    <span className="text-slate-900">{result.sha256}</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(result.sha256, 'sha256')}
                    className="p-1 hover:bg-slate-200 rounded text-slate-500"
                    title="Copy SHA-256"
                  >
                    {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                  <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <div className="truncate mr-2">
                      <span className="text-slate-400 font-sans mr-1 text-[10px] uppercase font-bold">MD5:</span>
                      <span className="text-slate-900">{result.md5}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(result.md5, 'md5')}
                      className="p-1 hover:bg-slate-200 rounded text-slate-500"
                    >
                      {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <div className="truncate mr-2">
                      <span className="text-slate-400 font-sans mr-1 text-[10px] uppercase font-bold">SHA-1:</span>
                      <span className="text-slate-900">{result.sha1}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(result.sha1, 'sha1')}
                      className="p-1 hover:bg-slate-200 rounded text-slate-500"
                    >
                      {copiedHash === 'sha1' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Detected Suspicious Patterns */}
              <div>
                <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-2">
                  Suspicious Static Signatures & String Indicators ({result.suspicious_patterns.length})
                </h4>
                {result.suspicious_patterns.length === 0 ? (
                  <p className="p-3 text-xs rounded bg-emerald-50 text-emerald-800 border border-emerald-200">
                    No known malicious string primitives or PE anomalies detected in binary static inspection.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {result.suspicious_patterns.map((pat, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg border border-red-200 bg-red-50/60 text-red-900 text-xs flex items-center justify-between"
                      >
                        <span className="font-mono text-[11px] font-medium">{pat}</span>
                        <SeverityBadge severity="High" size="sm" />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Reputation & Disclaimers */}
              <div className="p-3 rounded-lg bg-amber-50 text-amber-900 border border-amber-200 text-xs">
                <p className="font-bold mb-1">MANDATORY FORENSIC DISCLAIMER:</p>
                <p className="text-[11px] leading-relaxed">{result.disclaimer}</p>
                {result.reputation_lookup.notice && (
                  <p className="mt-1 text-[10px] font-mono text-amber-800">
                    {result.reputation_lookup.notice}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full min-h-[420px] bg-slate-50 rounded-lg border border-dashed border-slate-300 p-8 flex flex-col items-center justify-center text-center">
              <div className="w-12 h-12 rounded-full bg-slate-200 flex items-center justify-center text-slate-500 mb-3">
                <FileSearch className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-semibold text-slate-700">Awaiting File Inspection</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select an artifact from your workstation or load a preset simulated attack dropper above.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

function roundBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
