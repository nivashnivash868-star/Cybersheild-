import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { EventInvestigation } from '../components/investigation/EventInvestigation';
import { jsonResponse, mockApi } from './helpers';

const detail = (over: object = {}) => ({
  event: { event_id: 'ZT-1', timestamp: '2026-10-28T10:00:00', event_source: 'Zetaris / auth logs', threat_category: 'Credential Brute Force', risk_score: 80,
           severity: 'High', source_ip: '45.155.205.233', dest_ip: '10.20.0.1', domain: null, user_account: 'priya@corp.test', evidence: '14 failed logins',
           analysis_status: 'Analyzed', recommended_action: 'Block the address', is_simulated: true, is_acknowledged: false, ...over },
  related_events: [], timeline: [], automation: [{ tier: 'L1', decision: 'ESCALATED', reason: 'Matched rule', confidence: 0.9, at: '2026-10-28T10:01:00' }],
});

const ipRow = () => screen.getAllByText('45.155.205.233').map((e) => e.closest('li')).find(Boolean)!;

describe('EventInvestigation', () => {
  it('shows the evidence, labels simulated data and says how automation handled it', async () => {
    mockApi({ 'GET /events/ZT-1': detail() });
    render(<EventInvestigation eventId="ZT-1" onClose={() => undefined} />);
    expect(await screen.findByText('14 failed logins')).toBeInTheDocument();
    expect(screen.getByText('SIMULATED')).toBeInTheDocument();
    expect(screen.getByText(/Matched rule/)).toBeInTheDocument();
  });

  it('checks reputation on request and shows each provider honestly', async () => {
    const { calls } = mockApi({
      'GET /events/ZT-1': detail(),
      'GET /threat-intel/lookup?indicator=45.155.205.233': { indicator: '45.155.205.233', type: 'ip', malicious: true, suspicious: true, results: [
        { provider: 'abuseipdb', status: 'ok', verdict: 'malicious', summary: 'AbuseIPDB confidence of abuse 96%' },
        { provider: 'virustotal', status: 'not_configured', summary: 'VirusTotal is not configured.' }] },
    });
    render(<EventInvestigation eventId="ZT-1" onClose={() => undefined} />);
    await screen.findByText('14 failed logins');
    await userEvent.click(within(ipRow()).getByRole('button', { name: /check reputation/i }));
    expect(await screen.findByText(/confidence of abuse 96%/)).toBeInTheDocument();
    expect(screen.getByText(/VirusTotal is not configured/)).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith('/threat-intel/lookup'))).toBe(true);
  });

  it('shows the failure rather than a blank when a lookup is refused', async () => {
    mockApi({ 'GET /events/ZT-1': detail(), 'GET /threat-intel/lookup?indicator=45.155.205.233': () => jsonResponse(429, { detail: 'Too many lookups; slow down.' }) });
    render(<EventInvestigation eventId="ZT-1" onClose={() => undefined} />);
    await screen.findByText('14 failed logins');
    await userEvent.click(within(ipRow()).getByRole('button', { name: /check reputation/i }));
    expect(await screen.findByText('Too many lookups; slow down.')).toBeInTheDocument();
  });
});
