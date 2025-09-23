/**
 * Google Authentication Plugin for REST API
 *
 * GOOGLE-SPECIFIC: Handles Google One-Tap authentication and session management
 * Creates app-owned sessions with refresh tokens from Google ID tokens
 */

import { randomBytes, randomUUID } from 'crypto';
import { SignJWT, jwtVerify, createRemoteJWKSet } from 'jose';
import { normalizeGoogleToken } from './lib/jwtAuthNormalizers/google.js';

function toSeconds(duration, fallbackSeconds) {
  if (typeof duration === 'number') {
    return duration;
  }

  if (typeof duration !== 'string') {
    return fallbackSeconds;
  }

  const match = duration.trim().match(/^(\d+)([smhdw])$/i);
  if (!match) {
    return fallbackSeconds;
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();

  const unitMap = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60,
    w: 7 * 24 * 60 * 60
  };

  return value * (unitMap[unit] || 1);
}

function buildRefreshCookie(value, maxAgeSeconds, { secureCookie, sameSite = 'Lax' } = {}) {
  const parts = [
    `refresh_token=${value}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    'HttpOnly'
  ];

  if (secureCookie) {
    parts.push('Secure');
  }

  if (sameSite) {
    parts.push(`SameSite=${sameSite}`);
  }

  return parts.join('; ');
}

function buildRefreshRemovalCookie({ secureCookie, sameSite = 'Lax' } = {}) {
  const parts = [
    'refresh_token=',
    'Path=/',
    'Max-Age=0',
    'HttpOnly'
  ];

  if (secureCookie) {
    parts.push('Secure');
  }

  if (sameSite) {
    parts.push(`SameSite=${sameSite}`);
  }

  return parts.join('; ');
}

function buildCsrfCookie(value, maxAgeSeconds, { secureCookie, sameSite = 'Lax' } = {}) {
  const parts = [
    `refresh_csrf=${value}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`
  ];

  if (secureCookie) {
    parts.push('Secure');
  }

  if (sameSite) {
    parts.push(`SameSite=${sameSite}`);
  }

  return parts.join('; ');
}

function buildCsrfRemovalCookie({ secureCookie, sameSite = 'Lax' } = {}) {
  const parts = [
    'refresh_csrf=',
    'Path=/',
    'Max-Age=0'
  ];

  if (secureCookie) {
    parts.push('Secure');
  }

  if (sameSite) {
    parts.push(`SameSite=${sameSite}`);
  }

  return parts.join('; ');
}

function parseCookies(context) {
  const cookieHeader = context?.req?.headers?.cookie;
  const result = {};

  if (!cookieHeader) {
    return result;
  }

  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [name, ...rest] = cookie.trim().split('=');
    if (!name) continue;
    result[name] = decodeURIComponent(rest.join('='));
  }

  return result;
}

function getCookieValue(context, name) {
  const cookies = parseCookies(context);
  return cookies[name] || null;
}

function generateCsrfToken() {
  return randomBytes(32).toString('hex');
}

function validateCsrf(context) {
  const headerValue = context?.req?.headers?.['x-csrf-token'];
  const csrfHeader = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  const csrfCookie = getCookieValue(context, 'refresh_csrf');

  if (!csrfHeader || !csrfCookie) {
    return false;
  }

  return csrfHeader.trim() === csrfCookie.trim();
}

function generateTokenId() {
  if (typeof randomUUID === 'function') {
    return randomUUID();
  }
  return randomBytes(16).toString('hex');
}

export const GoogleAuthPlugin = {
  name: 'google-auth',
  dependencies: ['rest-api'],

  async install({ api, addHook, log, helpers, pluginOptions }) {
    log.info('Installing Google Authentication plugin');

    // GOOGLE-SPECIFIC: Configuration
    const clientId = pluginOptions.clientId;
    if (!clientId) {
      log.warn('GoogleAuthPlugin: No client ID provided, skipping setup');
      return;
    }

    const resolvedSessionSecret = (() => {
      const fromOptions = typeof pluginOptions.sessionSecret === 'string'
        ? pluginOptions.sessionSecret.trim()
        : '';
      if (fromOptions) return fromOptions;

      const fromEnv = typeof process.env.SESSION_SECRET === 'string'
        ? process.env.SESSION_SECRET.trim()
        : '';
      return fromEnv;
    })();

    if (!resolvedSessionSecret) {
      throw new Error('GoogleAuthPlugin: sessionSecret is required. Set pluginOptions.sessionSecret or the SESSION_SECRET environment variable.');
    }

    if (resolvedSessionSecret === 'google-session-secret') {
      throw new Error('GoogleAuthPlugin: sessionSecret must not use the built-in placeholder value. Provide a unique secret.');
    }

    const config = {
      clientId,
      sessionSecret: resolvedSessionSecret,
      sessionExpiry: pluginOptions.sessionExpiry || '30d',
      refreshExpiry: pluginOptions.refreshExpiry || '90d',
      usersResource: pluginOptions.usersResource || 'users',
      jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
      cookieSameSite: pluginOptions.cookieSameSite || 'Lax',
      cookieSecure: pluginOptions.cookieSecure !== undefined
        ? pluginOptions.cookieSecure
        : process.env.NODE_ENV === 'production'
    };

    // GOOGLE-SPECIFIC: JWKS for Google token verification
    const JWKS = createRemoteJWKSet(new URL(config.jwksUrl));

    // Convert session secret to Uint8Array for jose
    const secret = new TextEncoder().encode(config.sessionSecret);

    // GOOGLE-SPECIFIC: Add auth endpoints using api.addRoute
    if (api.addRoute) {
      // Exchange Google One-Tap token for app session
      await api.addRoute({
        method: 'POST',
        path: '/api/auth/google/one-tap',
        handler: async ({ body, context }) => {
          try {
            const { credential } = body;

            // Verify Google ID token
            const { payload } = await jwtVerify(credential, JWKS, {
              issuer: ['https://accounts.google.com', 'accounts.google.com'],
              audience: config.clientId
            });

            log.debug('Google token verified', {
              sub: payload.sub,
              email: payload.email
            });

            // Upsert user in database
            const user = await helpers.jwtAuth.upsertUser(
              payload.sub,
              {
                email: payload.email,
                name: payload.name,
                avatar_url: payload.picture  // Use standard field name
                // Removed: google_picture, google_verified_email (not needed)
              },
              'google'
            );

            const internalUserId = user?.id || user?.data?.id;
            const userData = user?.data || user;

            // Build linked_providers dynamically from configured providers
            const linked_providers = {};
            if (helpers.jwtAuth.getConfiguredProviders) {
              const configuredProviders = helpers.jwtAuth.getConfiguredProviders();
              configuredProviders.forEach(providerName => {
                const providerIdField = `${providerName}_id`;
                linked_providers[providerName] = userData[providerIdField] || null;
              });
            }

            // Create app-owned session token
            // Using standard JWT claims (RFC 7519) with minimal custom claims
            const accessTokenJti = generateTokenId();
            const sessionToken = await new SignJWT({
              sub: payload.sub,     // Standard 'subject' claim (Google provider ID)
              provider: 'google',   // Custom claim: which auth provider
              type: 'access'        // Custom claim: token type
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setIssuedAt()
              .setIssuer('app')
              .setAudience('app')
              .setJti(accessTokenJti)
              .setExpirationTime(config.sessionExpiry)
              .sign(secret);

            // Create refresh token
            const refreshTokenJti = generateTokenId();
            const refreshToken = await new SignJWT({
              sub: payload.sub,     // Standard 'subject' claim
              provider: 'google',   // Keep provider for consistency
              type: 'refresh'
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setIssuedAt()
              .setIssuer('app')
              .setAudience('app')
              .setJti(refreshTokenJti)
              .setExpirationTime(config.refreshExpiry)
              .sign(secret);

            // Normalize user data using the existing normalizer
            const normalizedUser = normalizeGoogleToken(payload);

            // Calculate expiry times
            const expiresIn = toSeconds(config.sessionExpiry, 30 * 24 * 60 * 60);
            const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
            const refreshMaxAge = toSeconds(config.refreshExpiry, 90 * 24 * 60 * 60);
            const refreshCookie = buildRefreshCookie(refreshToken, refreshMaxAge, {
              secureCookie: config.cookieSecure,
              sameSite: config.cookieSameSite
            });
            const csrfToken = generateCsrfToken();
            const csrfCookie = buildCsrfCookie(csrfToken, refreshMaxAge, {
              secureCookie: config.cookieSecure,
              sameSite: config.cookieSameSite
            });

            // Return unwrapped, standardized session format
            return {
              statusCode: 200,
              headers: {
                'Set-Cookie': [refreshCookie, csrfCookie]
              },
              body: {
                access_token: sessionToken,
                expires_in: expiresIn,
                expires_at: expiresAt,
                token_type: 'Bearer',
                provider: 'google',
                provider_id: payload.sub,  // Provider ID at root level
                user: {
                  id: String(internalUserId),  // Ensure string for consistency
                  email: normalizedUser.email,
                  email_verified: normalizedUser.email_verified,
                  name: normalizedUser.name,
                  avatar_url: normalizedUser.avatar_url,  // Normalized field name
                  phone: normalizedUser.phone || null,
                  username: null,
                  created_at: userData.created_at,
                  updated_at: userData.updated_at
                }
              }
            };

          } catch (error) {
            log.error('Google One-Tap exchange failed:', error.message || error);
            return {
              statusCode: 401,
              body: { error: error.message || 'Invalid Google token' }
            };
          }
        }
      });

      // Refresh token endpoint
      await api.addRoute({
        method: 'POST',
        path: '/api/auth/google/refresh',
        handler: async ({ body, context }) => {
          try {
            const csrfCookie = getCookieValue(context, 'refresh_csrf');
            if (csrfCookie && !validateCsrf(context)) {
              return {
                statusCode: 403,
                body: { error: 'INVALID_CSRF_TOKEN' }
              };
            }

            let refreshToken = body?.refresh_token;
            if (!refreshToken) {
              refreshToken = getCookieValue(context, 'refresh_token');
            }

            if (!refreshToken) {
              throw new Error('Missing refresh token');
            }

            const { payload } = await jwtVerify(refreshToken, secret, {
              issuer: 'app',
              audience: 'app'
            });

            if (payload.type !== 'refresh') {
              throw new Error('Invalid token type');
            }

            if (payload.jti && helpers.jwtAuth?.revokeToken) {
              try {
                let revocationUserId = `google:${payload.sub}`;
                if (helpers.jwtAuth.getUserByProviderId) {
                  const existingUser = await helpers.jwtAuth.getUserByProviderId(payload.sub, 'google');
                  if (existingUser?.id) {
                    revocationUserId = existingUser.id;
                  }
                }

                await helpers.jwtAuth.revokeToken(payload.jti, revocationUserId, payload.exp || Math.floor(Date.now() / 1000));
              } catch (revokeError) {
                log.error('Failed to revoke previous refresh token', {
                  error: revokeError?.message || revokeError,
                  jti: payload.jti,
                  sub: payload.sub
                });
              }
            }

            // Issue new access token
            const newAccessTokenJti = generateTokenId();
            const sessionToken = await new SignJWT({
              sub: payload.sub,     // Standard 'subject' claim
              provider: 'google',
              type: 'access'
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setIssuedAt()
              .setIssuer('app')
              .setAudience('app')
              .setJti(newAccessTokenJti)
              .setExpirationTime(config.sessionExpiry)
              .sign(secret);

            const newRefreshTokenJti = generateTokenId();
            const newRefreshToken = await new SignJWT({
              sub: payload.sub,
              provider: 'google',
              type: 'refresh'
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setIssuedAt()
              .setIssuer('app')
              .setAudience('app')
              .setJti(newRefreshTokenJti)
              .setExpirationTime(config.refreshExpiry)
              .sign(secret);

            const refreshMaxAge = toSeconds(config.refreshExpiry, 90 * 24 * 60 * 60);
            const refreshCookie = buildRefreshCookie(newRefreshToken, refreshMaxAge, {
              secureCookie: config.cookieSecure,
              sameSite: config.cookieSameSite
            });
            const newCsrfToken = generateCsrfToken();
            const newCsrfCookie = buildCsrfCookie(newCsrfToken, refreshMaxAge, {
              secureCookie: config.cookieSecure,
              sameSite: config.cookieSameSite
            });

            return {
              statusCode: 200,
              headers: {
                'Set-Cookie': [refreshCookie, newCsrfCookie]
              },
              body: {
                access_token: sessionToken,
                expires_in: toSeconds(config.sessionExpiry, 30 * 24 * 60 * 60)
              }
            };

          } catch (error) {
            log.error('Google refresh failed:', error);
            return {
              statusCode: 401,
              body: { error: 'Invalid refresh token' }
            };
          }
        }
      });

      await api.addRoute({
        method: 'POST',
        path: '/api/auth/google/logout',
        handler: async ({ context }) => {
          if (!validateCsrf(context)) {
            return {
              statusCode: 403,
              body: { error: 'INVALID_CSRF_TOKEN' }
            };
          }

          const existingRefreshToken = getCookieValue(context, 'refresh_token');
          if (existingRefreshToken) {
            try {
              const { payload } = await jwtVerify(existingRefreshToken, secret, {
                issuer: 'app',
                audience: 'app'
              });

              if (payload.jti && helpers.jwtAuth?.revokeToken) {
                let revocationUserId = `google:${payload.sub}`;
                if (helpers.jwtAuth.getUserByProviderId) {
                  const existingUser = await helpers.jwtAuth.getUserByProviderId(payload.sub, 'google');
                  if (existingUser?.id) {
                    revocationUserId = existingUser.id;
                  }
                }

                await helpers.jwtAuth.revokeToken(payload.jti, revocationUserId, payload.exp || Math.floor(Date.now() / 1000));
              }
            } catch (verifyError) {
              log.warn('Failed to verify refresh token during logout', {
                error: verifyError?.message || verifyError
              });
            }
          }

          const removalCookie = buildRefreshRemovalCookie({
            secureCookie: config.cookieSecure,
            sameSite: config.cookieSameSite
          });
          const csrfRemovalCookie = buildCsrfRemovalCookie({
            secureCookie: config.cookieSecure,
            sameSite: config.cookieSameSite
          });

          return {
            statusCode: 200,
            headers: {
              'Set-Cookie': [removalCookie, csrfRemovalCookie]
            },
            body: { success: true }
          };
        }
      });

      await api.addRoute({
        method: 'POST',
        path: '/api/auth/google/link',
        handler: async ({ body, context }) => {
          try {
            if (!context.auth?.userId) {
              return {
                statusCode: 401,
                body: { error: 'AUTH_REQUIRED', message: 'Must be logged in to link accounts' }
              };
            }

            const csrfCookie = getCookieValue(context, 'refresh_csrf');
            if (csrfCookie && !validateCsrf(context)) {
              return {
                statusCode: 403,
                body: { error: 'INVALID_CSRF_TOKEN' }
              };
            }

            const { credential } = body || {};
            if (!credential) {
              return {
                statusCode: 400,
                body: { error: 'MISSING_CREDENTIAL', message: 'Google credential is required' }
              };
            }

            const { payload } = await jwtVerify(credential, JWKS, {
              issuer: ['https://accounts.google.com', 'accounts.google.com'],
              audience: config.clientId
            });

            const currentUser = await helpers.jwtAuth.getUser(context.auth.userId);
            if (!currentUser) {
              return {
                statusCode: 404,
                body: { error: 'USER_NOT_FOUND' }
              };
            }

            if (payload.email && currentUser.email && payload.email !== currentUser.email) {
              return {
                statusCode: 400,
                body: {
                  error: 'EMAIL_MISMATCH',
                  message: 'Google account email must match your existing account email'
                }
              };
            }

            const existingLinked = await helpers.jwtAuth.getUserByProviderId(payload.sub, 'google');
            if (existingLinked && String(existingLinked.id) !== String(currentUser.id)) {
              return {
                statusCode: 400,
                body: {
                  error: 'ALREADY_LINKED',
                  message: 'This Google account is already linked to another user'
                }
              };
            }

            await api.resources[config.usersResource].patch({
              id: currentUser.id,
              google_id: payload.sub,
              google_email: payload.email || currentUser.google_email || null
            }, { auth: { userId: currentUser.id, system: true } });

            log.info('Linked Google account to user', {
              userId: currentUser.id,
              googleId: payload.sub
            });

            return {
              statusCode: 200,
              body: {
                success: true,
                provider: 'google'
              }
            };
          } catch (error) {
            log.error('Google account linking failed:', error);
            return {
              statusCode: 500,
              body: { error: 'LINK_FAILED', message: error.message || 'Failed to link Google account' }
            };
          }
        }
      });

      log.info('Added Google auth endpoints: /api/auth/google/one-tap, /api/auth/google/refresh, /api/auth/google/logout, /api/auth/google/link');
    }

    // GOOGLE-SPECIFIC: Register as JWT provider for app-issued tokens
    addHook('jwt:register-provider', 'google-provider', {}, async ({ context }) => {
      context.providers.google = {
        secret: config.sessionSecret,  // App's secret, not Google's
        algorithms: ['HS256'],         // App's algorithm
        issuer: 'app',
        audience: 'app',
        userIdField: 'sub',            // Standard JWT claim for subject
        emailField: 'email'
      };

      log.info('Google registered as JWT auth provider (app-issued tokens)');
    });

    // GOOGLE-SPECIFIC: Add Google fields to users schema
    addHook('schema:enrich', 'google-extend-users-schema', {}, async ({ context }) => {
      const { fields, scopeName } = context;

      if (scopeName !== config.usersResource) return;

      const googleFields = {
        google_id: { type: 'string', nullable: true, unique: true, indexed: true, search: true },
        google_email: { type: 'string', nullable: true }  // Current email at Google
        // Removed: google_picture (use avatar_url), google_name (use name), google_verified_email (not needed)
      };

      Object.assign(fields, googleFields);
      log.debug(`Extended ${scopeName} with Google fields`);
    });

    log.info('GoogleAuthPlugin installed successfully');
  }
}
