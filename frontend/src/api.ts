/**
 * Sentinel AI — API base URL helper
 *
 * In development: Vite proxies /api → localhost:8000, so API_BASE is empty.
 * In production (Render): VITE_API_BASE_URL is set to the backend Render URL,
 * e.g. https://sentinel-ai-backend.onrender.com
 */

export const API_BASE: string = import.meta.env.VITE_API_BASE_URL ?? '';

/**
 * WebSocket base URL — converts https:// → wss:// and http:// → ws://
 * Falls back to current page origin if no env var set (dev mode).
 */
export const WS_BASE: string = API_BASE
  ? API_BASE.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://')
  : (typeof window !== 'undefined'
      ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
      : 'ws://localhost:8000');

/** Convenience wrapper — joins API_BASE with a path */
export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

/** Dashboard API requests need the browser's secure, HttpOnly session cookie. */
export function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  let token: string | null = null;
  try { token = typeof window === 'undefined' ? null : window.sessionStorage.getItem('sentinel_session'); } catch { token = null; }
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(input, { ...init, headers, credentials: 'include' });
}
