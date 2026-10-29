import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { SocOperationsPage } from '../pages/SocOperationsPage';
import { mockApi } from './helpers';

const overview = (connector = false) => ({
  l1: { events_total: 20, triaged: 20, waiting: 0, auto_closed: 15, duplicates: 1, escalated: 4 },
  l2: { incidents_investigated: 1, waiting: 0, true_positive: 1, needs_human: 0, false_positive: 0, auto_closed_incidents: 0 },
  l3: { pending: 2, approved: 0, rejected: 0, pending_by_kind: {}, active_rules: 0 }, automation_rate: 0.8,
  response_connector: { configured: connector, actions: connector ? ['DISABLE_ACCOUNT', 'HOST_ISOLATION'] : [] },
});
const decision = (id: number, kind: string, requires_admin: boolean, proposal: object) => ({
  id, kind, requires_admin, incident_id: 'INC-1', title: `Decision ${id}`, rationale: 'why', evidence: ['e1'], proposal, priority: 'High',
  status: 'PENDING', created_by: 'agent:L2', created_at: '2026-10-28T10:00:00', decided_by: null, decided_at: null, decision_note: null, outcome: null,
});
const pending = [decision(1, 'CONTAINMENT', false, { indicator: '45.155.205.233', ttl_hours: 24 }),
                 decision(2, 'HOST_ISOLATION', true, { host: '10.20.4.37' }), decision(3, 'DISABLE_ACCOUNT', true, { account: 'priya@corp.test' })];
const routes = (connector = false, decisions: unknown[] = pending) => ({
  'GET /soc/overview': overview(connector), 'GET /soc/decisions?status=PENDING': decisions, 'GET /soc/decisions?status=All': [],
  'GET /soc/activity?limit=40&tier=L2': [], 'GET /soc/rules': [],
});
const person = (role: string) => ({ id: 1, email: 'p@corp.test', name: 'P', role, department: 'SOC', is_active: true, mfa_enabled: true }) as never;

describe('SOC operations: who may decide', () => {
  it('lets an analyst approve a block but makes them wait for an administrator on account and host actions', async () => {
    mockApi(routes());
    render(<SocOperationsPage currentUser={person('SOC Analyst')} onSelectIncident={() => undefined} />);
    await screen.findByText('Decision 1');
    expect(screen.getAllByRole('button', { name: /approve/i })).toHaveLength(1);                 // only the block
    expect(screen.getAllByText(/Waiting for a Security Administrator/)).toHaveLength(2);
  });

  it('gives an administrator every Approve button and sends the decision with the note', async () => {
    const { calls } = mockApi({ ...routes(), 'POST /soc/decisions/2/decide': { id: 2 } });
    render(<SocOperationsPage currentUser={person('Security Administrator')} onSelectIncident={() => undefined} />);
    await screen.findByText('Decision 2');
    expect(screen.getAllByRole('button', { name: /approve/i })).toHaveLength(3);
    await userEvent.type(screen.getAllByPlaceholderText(/your reasoning/i)[1], 'confirmed in EDR');
    await userEvent.click(screen.getAllByRole('button', { name: /approve/i })[1]);
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/soc/decisions/2/decide')).toBe(true));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(JSON.parse(post.init!.body as string)).toEqual({ decision: 'approve', note: 'confirmed in EDR' });
  });

  it('says a manual step remains when no response connector is configured', async () => {
    mockApi(routes(false));
    render(<SocOperationsPage currentUser={person('Security Administrator')} onSelectIncident={() => undefined} />);
    expect(await screen.findByText(/still a manual step/)).toBeInTheDocument();
    expect(screen.getByText(/no response connector is configured/)).toBeInTheDocument();
  });

  it('describes the signed hand-off, and its confirmation rule, when a connector is configured', async () => {
    mockApi(routes(true));
    render(<SocOperationsPage currentUser={person('Security Administrator')} onSelectIncident={() => undefined} />);
    expect(await screen.findAllByText(/counts as done only when the connector confirms/)).toHaveLength(2);
    expect(screen.queryByText(/still a manual step/)).toBeNull();
  });

  it('says so when nothing needs a decision', async () => {
    mockApi(routes(false, []));
    render(<SocOperationsPage currentUser={person('SOC Analyst')} onSelectIncident={() => undefined} />);
    expect(await screen.findByText('Nothing needs a decision right now.')).toBeInTheDocument();
  });
});
