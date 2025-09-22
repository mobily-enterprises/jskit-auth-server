/**
 * Supabase Authentication Plugin for REST API
 * 
 * This plugin provides:
 * 1. Supabase provider registration for JWT plugin
 * 2. Schema extension for Supabase-specific user fields
 * 3. Support for anonymous users and OAuth providers
 * 
 * User synchronization is now handled automatically by the JWT plugin
 * when users make their first authenticated request.
 * 
 * Requirements:
 * - JWT plugin must be installed after this plugin
 * - App must define a users resource
 */

import { jwtVerify } from 'jose';

function getCookieValue(context, name) {
  const cookieHeader = context?.req?.headers?.cookie;
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [cookieName, ...rest] = cookie.trim().split('=');
    if (cookieName === name) {
      return decodeURIComponent(rest.join('='));
    }
  }
  return null;
}

export const SupabaseAuthPlugin = {
  name: 'supabase-auth',
  dependencies: ['rest-api'],
  
  async install({ api, addHook, log, helpers, pluginOptions }) {
    log.info('Installing Supabase Authentication plugin');
    
    const config = {
      usersResource: pluginOptions.usersResource || 'users',
      secret: pluginOptions.secret || pluginOptions.jwtSecret
    };
    
    log.debug('Supabase plugin configuration', config);
    
    // Register Supabase as an auth provider when JWT plugin asks
    addHook('jwt:register-provider', 'supabase-provider', {}, async ({ context }) => {
      // Check if secret is provided
      if (!config.secret) {
        log.warn('SupabaseAuthPlugin: No JWT secret provided, cannot register as provider');
        return;
      }
      
      // Add Supabase provider configuration
      context.providers.supabase = {
        secret: config.secret,
        algorithms: pluginOptions.algorithms || ['HS256'],
        userIdField: pluginOptions.userIdField || 'sub',
        emailField: pluginOptions.emailField || 'email'
      };
      
      log.info('Supabase registered as JWT auth provider');
    });
    
    // Extend users schema with Supabase fields
    addHook('schema:enrich', 'supabase-extend-users-schema', {}, async ({ context }) => {

      const { fields, scopeName } = context

      // Only modify the users resource
      if (scopeName !== config.usersResource) {
        log.trace(`Skipping schema enrichment for ${scopeName} (not users resource)`);
        return;
      }
      
      log.debug(`Extending ${scopeName} schema with Supabase fields`);
      
      // Add Supabase-specific fields (prefixed to avoid conflicts)
      const supabaseFields = {
        supabase_id: { type: 'string', nullable: true, unique: true, indexed: true, search: true },
        supabase_email: { type: 'string', nullable: true }  // Current email at Supabase
      };
      
      // Merge fields into the mutable fields object
      Object.assign(fields, supabaseFields);
      
      log.info(`Extended ${scopeName} with Supabase fields`, {
        fields: Object.keys(supabaseFields),
        resource: scopeName
      });
    });
    
    if (api.addRoute) {
      await api.addRoute({
        method: 'POST',
        path: '/api/auth/supabase/link',
        handler: async ({ body, context }) => {
          try {
            if (!context.auth?.userId) {
              return {
                statusCode: 401,
                body: { error: 'AUTH_REQUIRED', message: 'Must be logged in to link accounts' }
              };
            }

            const { access_token: accessToken } = body || {};
            if (!accessToken) {
              return {
                statusCode: 400,
                body: { error: 'MISSING_TOKEN', message: 'Supabase access token is required' }
              };
            }

            const currentUser = await helpers.jwtAuth.getUser(context.auth.userId);
            if (!currentUser) {
              return {
                statusCode: 404,
                body: { error: 'USER_NOT_FOUND' }
              };
            }

            const csrfCookie = getCookieValue(context, 'refresh_csrf');
            if (csrfCookie) {
              const headerValue = context?.req?.headers?.['x-csrf-token'];
              const csrfHeader = Array.isArray(headerValue) ? headerValue[0] : headerValue;
              if (!csrfHeader || csrfHeader.trim() !== csrfCookie.trim()) {
                return {
                  statusCode: 403,
                  body: { error: 'INVALID_CSRF_TOKEN' }
                };
              }
            }

            const { payload } = await jwtVerify(accessToken, new TextEncoder().encode(config.secret));

            const supabaseId = payload.sub;
            const supabaseEmail = payload.email;

            if (supabaseEmail && currentUser.email && supabaseEmail !== currentUser.email) {
              return {
                statusCode: 400,
                body: {
                  error: 'EMAIL_MISMATCH',
                  message: 'Supabase account email must match your existing account email'
                }
              };
            }

            const existingLinked = await helpers.jwtAuth.getUserByProviderId(supabaseId, 'supabase');
            if (existingLinked && String(existingLinked.id) !== String(currentUser.id)) {
              return {
                statusCode: 400,
                body: {
                  error: 'ALREADY_LINKED',
                  message: 'This Supabase account is already linked to another user'
                }
              };
            }

            await api.resources[config.usersResource].patch({
              id: currentUser.id,
              supabase_id: supabaseId,
              supabase_email: supabaseEmail || currentUser.supabase_email || null
            }, { auth: { userId: currentUser.id, system: true } });

            log.info('Linked Supabase account to user', {
              userId: currentUser.id,
              supabaseId
            });

            return {
              statusCode: 200,
              body: {
                success: true,
                provider: 'supabase'
              }
            };
          } catch (error) {
            log.error('Supabase account linking failed:', error);
            return {
              statusCode: 500,
              body: { error: 'LINK_FAILED', message: error.message || 'Failed to link Supabase account' }
            };
          }
        }
      });
    }

    log.info('SupabaseAuthPlugin installed successfully', {
      usersResource: config.usersResource,
      autoSync: 'Enabled via JWT plugin'
    });
  }
}
