export function createRefreshCookie(token, maxAgeSeconds, options = {}) {
  const parts = [
    `refresh_token=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    'HttpOnly'
  ];
  if (options.secure) parts.push('Secure');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  return parts.join('; ');
}

export function createCsrfCookie(token, maxAgeSeconds, options = {}) {
  const parts = [
    `refresh_csrf=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`
  ];
  if (options.secure) parts.push('Secure');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  return parts.join('; ');
}

export function parseCookies(req) {
  const header = req.headers?.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    cookies[name] = decodeURIComponent(rest.join('='));
  });
  return cookies;
}

export function getCsrfToken(req) {
  const headerValue = req.headers?.['x-csrf-token'];
  if (!headerValue) return null;
  return Array.isArray(headerValue) ? headerValue[0] : headerValue;
}
