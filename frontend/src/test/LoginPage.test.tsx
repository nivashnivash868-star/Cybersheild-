import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { LoginPage } from '../pages/LoginPage';
import { ThemeProvider } from '../context/ThemeContext';
import { jsonResponse, mockApi } from './helpers';

const user = { id: 1, email: 'a@corp.test', full_name: 'Alex', role: 'SOC Analyst', department: 'SOC', is_active: true, mfa_enabled: false };
const state = (over: object = {}) => ({ user, mfa_state: 'ok', must_change_password: false, ...over });
const renderLogin = (onLoginSuccess = vi.fn()) => {
  render(<ThemeProvider><LoginPage onLoginSuccess={onLoginSuccess} /></ThemeProvider>);
  return onLoginSuccess;
};
const ssoOff = { 'GET /auth/sso/config': { enabled: false, provider_name: 'x' } };

describe('LoginPage', () => {
  it('signs in and hands the session to the app', async () => {
    mockApi({ ...ssoOff, 'POST /auth/login': state() });
    const done = renderLogin();
    await userEvent.type(screen.getByPlaceholderText('you@company.com'), 'a@corp.test');
    await userEvent.type(screen.getByPlaceholderText('Enter your password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });

  it('shows the server message for a failed sign-in and does not proceed', async () => {
    mockApi({ ...ssoOff, 'POST /auth/login': () => jsonResponse(401, { detail: 'Incorrect email or password.' }) });
    const done = renderLogin();
    await userEvent.type(screen.getByPlaceholderText('you@company.com'), 'a@corp.test');
    await userEvent.type(screen.getByPlaceholderText('Enter your password'), 'wrong-password');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByText('Incorrect email or password.')).toBeInTheDocument();
    expect(done).not.toHaveBeenCalled();
  });

  it('asks for the authenticator code when the account has two-step verification', async () => {
    mockApi({ ...ssoOff, 'POST /auth/login': state({ mfa_state: 'verify' }), 'POST /auth/mfa/verify': state() });
    const done = renderLogin();
    await userEvent.type(screen.getByPlaceholderText('you@company.com'), 'a@corp.test');
    await userEvent.type(screen.getByPlaceholderText('Enter your password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    const code = await screen.findByRole('textbox');
    expect(done).not.toHaveBeenCalled();
    await userEvent.type(code, '123456');
    await userEvent.click(screen.getByRole('button', { name: /verify|continue|confirm/i }));
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });

  it('offers single sign-on only when the server has it configured, pointing at the API', async () => {
    mockApi({ 'GET /auth/sso/config': { enabled: true, provider_name: 'Contoso' } });
    renderLogin();
    const link = await screen.findByRole('link', { name: /continue with contoso/i });
    expect(link).toHaveAttribute('href', '/api/v1/auth/sso/login');
  });

  it('shows no SSO button when it is off', async () => {
    mockApi(ssoOff);
    renderLogin();
    await screen.findByPlaceholderText('you@company.com');
    expect(screen.queryByRole('link', { name: /continue with/i })).toBeNull();
  });

  it('explains a refused SSO attempt without revealing why, and cleans the URL', async () => {
    window.history.pushState({}, '', '/?sso_error=denied');
    mockApi(ssoOff);
    renderLogin();
    expect(await screen.findByRole('alert')).toHaveTextContent(/single sign-on was refused/i);
    expect(window.location.search).toBe('');
  });
});
