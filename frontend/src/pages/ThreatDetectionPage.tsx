import React, { useState } from 'react';
import { PhishingPage } from './PhishingPage';
import { FileAnalysisPage } from './FileAnalysisPage';
import { NetworkAnomalyPage } from './NetworkAnomalyPage';
import { EventTable } from '../components/events/EventTable';
import { SecurityEvent } from '../types';

type Tab = 'phishing' | 'url' | 'files' | 'network';

interface Props {
  initialSubTab?: Tab;
  onOpenIncident?: (id: string) => void;
}

const isPhishing = (e: SecurityEvent) => /(phish|bec|impersonation|spoof|credential harvest)/i.test(`${e.threat_category} ${e.event_source}`);

export const ThreatDetectionPage: React.FC<Props> = ({ initialSubTab = 'phishing', onOpenIncident }) => {
  const [subTab, setSubTab] = useState<Tab>(initialSubTab);
  const include = isPhishing;
  const tab = (id: Tab, label: string) => (
    <button key={id} onClick={() => setSubTab(id)} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${subTab === id ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>{label}</button>
  );
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        {tab('phishing', 'Phishing Detections')}{tab('url', 'URL Scanner')}{tab('files', 'File Analysis')}{tab('network', 'Network Anomalies')}
      </div>
      {subTab === 'url' ? <PhishingPage initialSubmissionType="url" />
        : subTab === 'files' ? <FileAnalysisPage />
        : subTab === 'network' ? <NetworkAnomalyPage />
        : <EventTable title="Phishing Detections" subtitle="Every phishing and impersonation detection, from all sources" include={include}
            emptyText="No phishing detections in this period." exportName="cybershield-phishing" onOpenIncident={onOpenIncident} />}
    </div>
  );
};
