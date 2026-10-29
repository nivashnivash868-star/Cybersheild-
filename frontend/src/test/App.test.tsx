import { act, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import { UNAUTHORIZED_EVENT } from '../api/client';
import { ThemeProvider } from '../context/ThemeContext';
import { jsonResponse, mockApi } from './helpers';

const session = (role: string, over: object = {}) => ({
  user: { id: 1, email: 'p@corp.test', full_name: 'Pat', role, department: 'SOC', is_active: true, mfa_enabled: true }, mfa_state: 'ok', must_change_password: false, ...over,
});
const quiet = { 'GET /auth/sso/config': { enabled: false, provider_name: '' } };
const renderApp = () => render(<ThemeProvider><App /></ThemeProvider>);

describe('App access', () => {
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => undefined); });

  it('shows the sign-in screen, not the product, to someone without a session', async () => {
    mockApi({ ...quiet, 'GET /auth/me': () => jsonResponse(401, { detail: 'Not signed in.' }) });
    renderApp();
    expect(await screen.findByPlaceholderText('you@company.com')).toBeInTheDocument();
    expect(screen.queryByText('Administration')).toBeNull();
  });

  it('lands an administrator in the administrator area', async () => {
    mockApi({ ...quiet, 'GET /auth/me': session('Security Administrator') });
    renderApp();
    expect(await screen.findByText('Administration')).toBeInTheDocument();
    expect(screen.getByText('Admin Overview')).toBeInTheDocument();
  });

  it('does not let a SOC analyst see administration', async () => {
    mockApi({ ...quiet, 'GET /auth/me': session('SOC Analyst') });
    renderApp();
    expect(await screen.findByText('Incident Management')).toBeInTheDocument();
    expect(screen.queryByText('Administration')).toBeNull();
  });

  it('keeps someone who has not finished two-step verification on the sign-in flow', async () => {
    mockApi({ ...quiet, 'GET /auth/me': session('SOC Analyst', { mfa_state: 'verify' }) });
    renderApp();
    expect(await screen.findByRole('textbox')).toBeInTheDocument();
    expect(screen.queryByText('Incident Management')).toBeNull();
  });

  it('returns to sign-in when the server ends the session', async () => {
    mockApi({ ...quiet, 'GET /auth/me': session('SOC Analyst') });
    renderApp();
    await screen.findByText('Incident Management');
    await act(async () => { window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)); });
    expect(await screen.findByPlaceholderText('you@company.com')).toBeInTheDocument();
  });
});
