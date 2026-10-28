import React, { useCallback, useState } from 'react';
import { EventTable } from '../components/events/EventTable';
import { MonitoringSourcesPage } from './MonitoringSourcesPage';
import { SecurityEvent } from '../types';

interface Props {
  initialSubTab?: 'web' | 'email' | 'files' | 'sources';
  onOpenIncident?: (id: string) => void;
}

const text = (e: SecurityEvent) => `${e.threat_category} ${e.event_source}`.toLowerCase();
const AREAS = {
  web: {
    title: 'Web Activity Monitoring', subtitle: 'Detections involving websites, DNS and outbound connections',
    include: (e: SecurityEvent) => !!e.domain || /(url|web|dns|domain|c2|beacon|proxy|gateway|egress|exfil|traffic)/.test(text(e)),
    empty: 'No web or network detections in this period.',
  },
  email: {
    title: 'Email Security', subtitle: 'Phishing, impersonation and malicious-message detections',
    include: (e: SecurityEvent) => /(email|mail|phish|bec|impersonation|spoof|credential harvest)/.test(text(e)),
    empty: 'No email detections in this period.',
  },
  files: {
    title: 'File & Data Monitoring', subtitle: 'Malware, suspicious files and leaked secrets',
    include: (e: SecurityEvent) => !!e.file_hash || /(file|malware|payload|dropper|ransom|dlp|secret|leak|macro|script)/.test(text(e)),
    empty: 'No file or data-exposure detections in this period.',
  },
} as const;

export const MonitoringCenterPage: React.FC<Props> = ({ initialSubTab = 'web', onOpenIncident }) => {
  const [subTab, setSubTab] = useState(initialSubTab);
  const tab = (id: typeof subTab, label: string) => (
    <button key={id} onClick={() => setSubTab(id)} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${subTab === id ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>{label}</button>
  );
  const area = subTab === 'sources' ? null : AREAS[subTab];
  const include = useCallback((e: SecurityEvent) => (area ? area.include(e) : false), [area]);
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        {tab('web', 'Web Activity')}{tab('email', 'Email Security')}{tab('files', 'File & Data Monitoring')}{tab('sources', 'Data Sources')}
      </div>
      {area ? (
        <EventTable key={subTab} title={area.title} subtitle={area.subtitle} include={include} emptyText={area.empty} exportName={`cybershield-${subTab}`} onOpenIncident={onOpenIncident} />
      ) : <MonitoringSourcesPage />}
    </div>
  );
};
