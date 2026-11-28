/** Mirrors the API's redirect URI rules so the console can flag mistakes before saving (the API stays authoritative). */
export const MAX_REDIRECT_URIS = 20;

const LOOPBACK_HOSTS = new Set(['localhost', '[::1]']);

function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname) || /^127(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * Absolute HTTPS URL (plain HTTP only on loopback) with no fragment, user info or comma
 * (RFC 6749 §3.1.2, RFC 8252 §8.3). The value is stored and compared exactly as typed.
 */
export function isValidRedirectUri(value: string): boolean {
  const uri = value.trim();
  if (!uri || uri.includes(',') || uri.includes('#')) return false;

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  if (parsed.username || parsed.password) return false;
  if (parsed.protocol === 'https:') return true;
  return parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname);
}
