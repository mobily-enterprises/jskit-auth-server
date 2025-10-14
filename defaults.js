export const DEFAULT_CONFIG = {
  basePath: '/api/auth',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax'
  },
  refresh: {
    sessionLifetime: '30d',
    refreshLifetime: '90d',
    revocationTable: 'revoked_refresh_tokens',
    cleanupInterval: 60 * 60 * 1000
  }
}

export function resolveConfig (options = {}) {
  const resolved = {
    basePath: options.basePath || DEFAULT_CONFIG.basePath,
    cookie: {
      secure: options.cookie?.secure ?? DEFAULT_CONFIG.cookie.secure,
      sameSite: options.cookie?.sameSite || DEFAULT_CONFIG.cookie.sameSite
    },
    refresh: {
      sessionLifetime: options.refresh?.sessionLifetime || DEFAULT_CONFIG.refresh.sessionLifetime,
      refreshLifetime: options.refresh?.refreshLifetime || DEFAULT_CONFIG.refresh.refreshLifetime,
      revocationTable: options.refresh?.revocationTable || DEFAULT_CONFIG.refresh.revocationTable,
      cleanupInterval: options.refresh?.cleanupInterval ?? DEFAULT_CONFIG.refresh.cleanupInterval
    }
  }

  return resolved
}
