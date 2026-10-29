import { describe, expect, it, vi } from 'vitest';
import { api, UNAUTHORIZED_EVENT } from '../api/client';
import { jsonResponse, mockApi } from './helpers';

describe('api client', () => {
  it('sends the CSRF token on state-changing requests and never on reads', async () => {
    document.cookie = 'cs_csrf=tok123; path=/';
    const { calls } = mockApi({ 'GET /auth/me': { user: {}, mfa_state: 'ok' }, 'POST /auth/logout': { status: 'ok' } });
    await api.getMe().catch(() => undefined);
    await api.logout();
    const headers = (i: number) => calls[i].init?.headers as Record<string, string>;
    expect(headers(0)['X-CSRF-Token']).toBeUndefined();
    expect(headers(1)['X-CSRF-Token']).toBe('tok123');
  });

  it('always sends cookies and never puts a credential in the URL or an Authorization header', async () => {
    const { calls } = mockApi({ 'GET /soc/overview': {} });
    await api.getSocOverview();
    expect(calls[0].init?.credentials).toBe('include');
    expect(JSON.stringify(calls[0].init?.headers)).not.toMatch(/authorization/i);
    expect(calls[0].path).not.toMatch(/token|password/i);
  });

  it('turns an API error body into the message', async () => {
    mockApi({ 'GET /soc/overview': () => jsonResponse(403, { detail: 'Security Administrator required.' }) });
    await expect(api.getSocOverview()).rejects.toThrow('Security Administrator required.');
  });

  it('joins validation errors from FastAPI', async () => {
    mockApi({ 'POST /auth/login': () => jsonResponse(422, { detail: [{ msg: 'field required' }, { msg: 'too short' }] }) });
    await expect(api.login({ email: '', password: '' })).rejects.toThrow('field required; too short');
  });

  it('announces a lost session on 401 for ordinary calls but not for the sign-in probes', async () => {
    const seen = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, seen);
    mockApi({ 'GET /soc/overview': () => jsonResponse(401, { detail: 'x' }), 'GET /auth/me': () => jsonResponse(401, { detail: 'x' }) });
    await api.getSocOverview().catch(() => undefined);
    expect(seen).toHaveBeenCalledTimes(1);
    await api.getMe().catch(() => undefined);
    expect(seen).toHaveBeenCalledTimes(1);
    window.removeEventListener(UNAUTHORIZED_EVENT, seen);
  });

  it('encodes indicators so they cannot alter the query', async () => {
    const { calls } = mockApi({ 'GET /threat-intel/lookup': { indicator: 'x', type: 'ip', results: [], malicious: false, suspicious: false } });
    await api.threatIntel('1.2.3.4&refresh=true#x');
    expect(calls[0].path).toContain('indicator=1.2.3.4%26refresh%3Dtrue%23x');
  });
});
