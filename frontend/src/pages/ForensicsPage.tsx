import React, { useState, useEffect } from 'react';
import {
  Fingerprint, Clock, ShieldCheck, FileDown, Layers, CheckCircle2,
  AlertOctagon, ArrowRight, ExternalLink, Terminal, Tag
} from 'lucide-react';
import { api } from '../api/client';
import { ForensicInvestigation, IncidentDetail } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface Props {
  initialIncidentId?: string | null;
}

export const ForensicsPage: React.FC<Props> = ({ initialIncidentId }) => {
  const [incidentsList, setIncidentsList] = useState<IncidentDetail[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [forensics, setForensics] = useState<ForensicInvestigation | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.getIncidents().then((list) => {
      setIncidentsList(list);
      if (initialIncidentId) {
        setSelectedIncidentId(initialIncidentId);
      } else if (list.length > 0) {
        setSelectedIncidentId(list[0].incident_id);
      }
    }).catch(console.error);
  }, [initialIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) return;
    setLoading(true);
    api.getForensics(selectedIncidentId)
      .then(setForensics)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [selectedIncidentId]);

  const handleDownloadDossier = async () => {
    if (!selectedIncidentId) return;
    try {
      const text = await api.exportIncidentReportText(selectedIncidentId);
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `FORENSIC_DOSSIER_${selectedIncidentId}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert(`Dossier download failed: ${e.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">Digital Forensics Investigation Locker</h1>
          <p className="text-xs text-slate-500">
            Chain-of-custody preservation, chronological sensor timeline reconstruction, and sealed artifact analysis
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Incident Selector Dropdown */}
          <div className="flex items-center gap-1.5 bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-700">
            <span className="text-slate-400 font-medium">Case:</span>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-transparent font-bold text-sky-700 focus:outline-none cursor-pointer"
            >
              {incidentsList.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} — {inc.threat_category}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleDownloadDossier}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-600 text-white text-xs font-medium hover:bg-sky-700 transition shadow-xs"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>Download Sealed Dossier</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-xs text-slate-400 bg-white rounded-lg border border-slate-200">
          Reconstructing chronological forensic timeline...
        </div>
      ) : forensics ? (
        <div className="space-y-6">
          {/* Case Header Card */}
          <div className="bg-slate-900 text-slate-200 rounded-lg p-5 shadow-xs space-y-3 border border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-sm font-bold text-sky-400 bg-sky-950 px-2.5 py-0.5 rounded border border-sky-800">
                  {forensics.incident_id}
                </span>
                <SeverityBadge severity={forensics.severity} size="md" />
                <span className="text-xs text-slate-400 uppercase font-semibold">
                  Status: <strong className="text-white">{forensics.status}</strong>
                </span>
              </div>
              <div className="text-xs text-slate-400 font-mono">
                Sealed: {forensics.created_at}
              </div>
            </div>

            <div>
              <h2 className="text-base font-bold text-white tracking-tight">{forensics.title}</h2>
              <p className="text-xs text-slate-300 mt-1">{forensics.analyst_findings}</p>
            </div>

            {/* MITRE ATT&CK Tactics Pills */}
            <div className="flex items-center flex-wrap gap-2 pt-1">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                MITRE ATT&CK Mapping:
              </span>
              {forensics.mitre_attack_tactics.map((tac, i) => (
                <span
                  key={i}
                  className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700"
                >
                  {tac}
                </span>
              ))}
            </div>
          </div>

          {/* Artifacts Inventory Table */}
          <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
            <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Sealed Artifact Inventory ({forensics.artifacts.length})
                </h3>
                <p className="text-[11px] text-slate-500">
                  IPs, domains, hashes, and identity handles extracted with cryptographic provenance
                </p>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-medium">
                Chain-of-Custody Verified
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[10px]">
                    <th className="py-2.5 px-4">Artifact Type</th>
                    <th className="py-2.5 px-4">Indicator Value</th>
                    <th className="py-2.5 px-4">Sensor Relationship</th>
                    <th className="py-2.5 px-4">First Observed</th>
                    <th className="py-2.5 px-4">Risk Weight</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-normal">
                  {forensics.artifacts.map((art, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 font-mono text-[11px]">
                      <td className="py-2.5 px-4 font-sans font-semibold text-slate-700">{art.type}</td>
                      <td className="py-2.5 px-4 font-bold text-slate-900 break-all">{art.value}</td>
                      <td className="py-2.5 px-4 font-sans text-slate-600">{art.relation}</td>
                      <td className="py-2.5 px-4 text-slate-500 text-[10px]">{art.first_seen}</td>
                      <td className="py-2.5 px-4 font-sans font-bold text-red-600">{art.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Chronological Event Timeline */}
          <div className="bg-white rounded-lg border border-slate-200 shadow-xs p-5 space-y-4">
            <div className="pb-2 border-b border-slate-200">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-sky-600" />
                <span>Chronological Event Progression Timeline ({forensics.timeline.length} Checkpoints)</span>
              </h3>
              <p className="text-[11px] text-slate-500">
                Ascending sequence of alerts, sealed evidence items, analyst notes, and containment executions
              </p>
            </div>

            <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
              {forensics.timeline.map((item, i) => (
                <div key={i} className="relative group text-xs">
                  {/* Timeline Node Dot */}
                  <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-sky-600 ring-4 ring-white"></div>

                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 hover:border-slate-300 transition space-y-1.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between text-[11px] gap-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{item.event_type}</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-200 text-slate-700 text-[10px] font-medium">
                          {item.source}
                        </span>
                      </div>
                      <span className="font-mono text-slate-500 text-[10px]">{item.timestamp}</span>
                    </div>

                    <p className="text-slate-700 text-xs leading-relaxed">{item.description}</p>

                    {item.pivot_data && Object.keys(item.pivot_data).length > 0 && (
                      <div className="pt-1 flex flex-wrap gap-2 text-[10px] font-mono text-slate-600">
                        {Object.entries(item.pivot_data).map(([k, v]) =>
                          v ? (
                            <span key={k} className="bg-white px-2 py-0.5 rounded border border-slate-200">
                              {k}: {String(v)}
                            </span>
                          ) : null
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-xs text-slate-400 bg-white rounded-lg border border-slate-200">
          No incident selected.
        </div>
      )}
    </div>
  );
};
