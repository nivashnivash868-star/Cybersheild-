import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { AdministrationPage } from '../pages/AdministrationPage';
import { jsonResponse, mockApi } from './helpers';

const admin = { id: 2, email: 'sec@corp.test', name: 'Sec Admin', role: 'Security Administrator', department: 'SOC', is_active: true, mfa_enabled: true } as const;
const integrations = [
  { key: 'email', name: 'Email (SMTP)', configured: true, detail: 'smtp.corp.test' },
  { key: 'virustotal', name: 'Threat intelligence: VirusTotal', configured: true, detail: 'Key is set but no lookup has been made yet.', state: 'unverified' },
  { key: 'zetaris', name: 'Zetaris data sources', configured: false, detail: 'ZETARIS_ORG_ID is not set' },
  { key: null, name: 'Firewall / DNS blocklist feeds', configured: false, detail: 'Credentials are managed on the Blocklist page' },
];
const base = { 'GET /users': [], 'GET /admin/settings': [], 'GET /admin/permissions': [], 'GET /admin/integrations': integrations };

async function openConfig() {
  render(<AdministrationPage currentUser={admin as never} />);
  await userEvent.click(screen.getByRole('button', { name: 'Security configuration' }));
}
const rowFor = (name: string) => screen.getByText(name).closest('li')!;

describe('Security integrations panel', () => {
  it('does not call a configured integration "Connected" until something proved it', async () => {
    mockApi(base);
    await openConfig();
    expect(await screen.findByText('Email (SMTP)')).toBeInTheDocument();
    expect(rowFor('Email (SMTP)')).toHaveTextContent('Configured, not verified');
    expect(rowFor('Zetaris data sources')).toHaveTextContent('Not set up');
    expect(rowFor('Firewall / DNS blocklist feeds')).not.toHaveTextContent('Connected');
  });

  it('offers a Test button only where a test exists, and shows the real result', async () => {
    const { calls } = mockApi({ ...base, 'POST /admin/integrations/email/test': { key: 'email', ok: true, detail: 'The mail server accepted a message.', latency_ms: 42 } });
    await openConfig();
    await screen.findByText('Email (SMTP)');
    expect(within(rowFor('Firewall / DNS blocklist feeds')).queryByRole('button', { name: /test/i })).toBeNull();
    await userEvent.click(within(rowFor('Email (SMTP)')).getByRole('button', { name: 'Test' }));
    expect(await screen.findByText(/Test passed/)).toBeInTheDocument();
    expect(rowFor('Email (SMTP)')).toHaveTextContent('42 ms');
    expect(calls.find((c) => c.method === 'POST')?.path).toBe('/admin/integrations/email/test');
  });

  it('shows a failed test as failed, including the server message', async () => {
    mockApi({ ...base, 'POST /admin/integrations/virustotal/test': { key: 'virustotal', ok: false, detail: 'VirusTotal rejected the API key.', latency_ms: 120 } });
    await openConfig();
    await userEvent.click(within(await screen.findByText('Threat intelligence: VirusTotal').then((e) => e.closest('li')!)).getByRole('button', { name: 'Test' }));
    expect(await screen.findByText(/Test failed/)).toBeInTheDocument();
    expect(screen.getByText(/rejected the API key/)).toBeInTheDocument();
  });

  it('reports a request error as a failed test too', async () => {
    mockApi({ ...base, 'POST /admin/integrations/zetaris/test': () => jsonResponse(429, { detail: 'Too many tests; wait a minute.' }) });
    await openConfig();
    await userEvent.click(within((await screen.findByText('Zetaris data sources')).closest('li')!).getByRole('button', { name: 'Test' }));
    expect(await screen.findByText(/Too many tests/)).toBeInTheDocument();
  });
});
