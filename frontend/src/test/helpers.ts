import { vi } from 'vitest';

/** Replaces fetch with a router: `routes` maps "METHOD /path" (path without the /api/v1 prefix) to a body or a function. */
export function mockApi(routes: Record<string, unknown | ((init?: RequestInit) => unknown)>) {
  const calls: { method: string; path: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    const path = url.pathname.replace(/^\/api\/v1/, '') + url.search;
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ method, path, init });
    const key = Object.keys(routes).find((k) => k === `${method} ${path}` || k === `${method} ${url.pathname.replace(/^\/api\/v1/, '')}`);
    if (!key) return new Response(JSON.stringify({ detail: `no mock for ${method} ${path}` }), { status: 404 });
    const value = routes[key];
    const body = typeof value === 'function' ? (value as (i?: RequestInit) => unknown)(init) : value;
    if (body instanceof Response) return body;
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fn);
  return { calls, fn };
}

export const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
