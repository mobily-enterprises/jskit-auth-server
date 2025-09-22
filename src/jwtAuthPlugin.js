/**
 * JWT Authentication Plugin for REST API
 *
 * This plugin provides:
 * 1. JWT token validation and context population
 * 2. Provider registration and session normalization helpers
 * 3. Token revocation and logout support
 * 4. Helper methods for provider user synchronization
*/

// Import all provider normalizers (server-side can afford to load all)
import { normalizeSupabaseToken } from './lib/jwtAuthNormalizers/supabase.js';
import { normalizeGoogleToken } from './lib/jwtAuthNormalizers/google.js';

// Map of provider names to their normalizer functions
const tokenNormalizers = {
  supabase: normalizeSupabaseToken,
  google: normalizeGoogleToken
  // Add new providers here as they're created
};

import {
  verifyToken,
  decodeToken,
  createRevocationResource,
  checkRevocation,
  cleanupExpiredTokens
} from './lib/jwtAuthHelpers.js';

/* =========================================================================
 * PLUGIN EXPORTS
 * ========================================================================= */

/* =========================================================================
 * PLUGIN DEFINITION AND MAIN INSTALL FUNCTION
 * ========================================================================= */

export const JwtAuthPlugin = {
  name: 'jwt-auth',
  dependencies: ['rest-api'], // Requires REST API plugin for resource operations
  
  async install({ api, addHook, log, runHooks, helpers, vars, on, pluginOptions }) {
    
    /* -----------------------------------------------------------------------
     * INITIALIZATION
     * ----------------------------------------------------------------------- */
    
    log.info('Installing JWT Authentication plugin');
    
    // Use plugin options directly
    const jwtOptions = pluginOptions || {};
    log.debug('JWT plugin options received', { 
      hasProviders: !!jwtOptions.providers,
      defaultProvider: jwtOptions.defaultProvider,
      revocation: jwtOptions.revocation?.enabled
    });

    if (jwtOptions.autoOwnership) {
      log.warn('JwtAuthPlugin: autoOwnership configuration is no longer handled here. Install json-rest-api\'s AccessPlugin to manage permissions and ownership.');
    }

    if (jwtOptions.ownershipField) {
      log.warn('JwtAuthPlugin: ownershipField option is ignored. Configure ownership via the AccessPlugin instead.');
    }
    
    // Initialize plugin state
    // State is scoped to this install method and accessible via closure
    const state = {
      // Timer ID for periodic cleanup of expired revoked tokens
      cleanupJob: null,
      
      // In-memory storage for revoked tokens (alternative to database storage)
      // WARNING: Memory storage is cleared on restart - use database for production
      memoryRevocationStore: new Map()
    };
    
    /* -----------------------------------------------------------------------
     * CONFIGURATION PARSING
     * 
     * Parses and validates all configuration options with sensible defaults.
     * Configuration is divided into logical groups for clarity.
     * ----------------------------------------------------------------------- */
    
    // Initialize providers registry
    const providers = {};
    
    // Create a hook point for other plugins to register providers
    // This hook will be called by JWT plugin to collect providers
    const providerContext = { providers };
    await runHooks('jwt:register-provider', providerContext);
    
    // Also accept providers passed directly (for backward compatibility)
    if (jwtOptions.providers) {
      Object.entries(jwtOptions.providers).forEach(([name, providerConfig]) => {
        providers[name] = {
          secret: providerConfig.secret,
          publicKey: providerConfig.publicKey,
          jwksUrl: providerConfig.jwksUrl,
          algorithms: providerConfig.algorithms || ['HS256', 'RS256'],
          audience: providerConfig.audience,
          issuer: providerConfig.issuer,
          userIdField: providerConfig.userIdField || 'sub',
          emailField: providerConfig.emailField || 'email'
        };
        log.info(`Registered auth provider via config: ${name}`, {
          hasSecret: !!providerConfig.secret,
          hasPublicKey: !!providerConfig.publicKey,
          hasJwksUrl: !!providerConfig.jwksUrl,
          algorithms: providerConfig.algorithms || ['HS256', 'RS256'],
          userIdField: providerConfig.userIdField || 'sub',
          emailField: providerConfig.emailField || 'email'
        });
      });
    }
    
    // Validate we have at least one provider configured
    if (Object.keys(providers).length === 0) {
      log.error('No auth providers configured');
      throw new Error('JwtAuthPlugin requires at least one auth provider to be configured');
    }
    
    // Default provider to use when no header is specified
    const defaultProvider = jwtOptions.defaultProvider || Object.keys(providers)[0] || 'default';
    
    log.info('Auth providers collected', { 
      providers: Object.keys(providers),
      defaultProvider: defaultProvider,
      totalProviders: Object.keys(providers).length
    });
    
    const config = {
      // Store all provider configurations
      providers,
      defaultProvider,
      
      // Users resource configuration
      usersResource: jwtOptions.usersResource || 'users',
      
      // Account linking configuration
      // When enabled, automatically links accounts with the same email address
      autoLinkByEmail: jwtOptions.autoLinkByEmail || false, // Default: disabled for backward compatibility
      
      // Token revocation configuration
      // Supports both database and in-memory storage
      revocation: {
        enabled: jwtOptions.revocation?.enabled !== false,    // Default: enabled
        storage: jwtOptions.revocation?.storage || 'database', // 'database' or 'memory'
        cleanupInterval: jwtOptions.revocation?.cleanupInterval || 3600000, // 1 hour
        tableName: jwtOptions.revocation?.tableName || 'revoked_tokens'
      },
      
      // Optional REST endpoints
      // The plugin can automatically add logout and session endpoints
      endpoints: {
        logout: jwtOptions.endpoints?.logout || false,   // e.g., '/auth/logout'
        session: jwtOptions.endpoints?.session || false  // e.g., '/auth/session'
      }
    };
    
    /* -----------------------------------------------------------------------
     * CONFIGURATION VALIDATION
     * ----------------------------------------------------------------------- */
    
    // Ensure at least one provider is configured with a validation method
    const hasValidProvider = Object.values(config.providers).some(
      p => p.secret || p.publicKey || p.jwksUrl
    );
    
    if (!hasValidProvider) {
      log.error('No valid auth provider configured', { providers: Object.keys(config.providers) });
      throw new Error('JwtAuthPlugin requires at least one provider with secret, publicKey, or jwksUrl');
    }
    
    log.debug('JWT configuration validated', {
      providersCount: Object.keys(config.providers).length,
      revocation: config.revocation.enabled
    });
    
    /* -----------------------------------------------------------------------
     * JWKS CLIENT SETUP
     * 
     * For Auth0, Supabase, and other providers that use rotating keys.
     * The JWKS client fetches public keys dynamically based on the 'kid' claim.
     * 
     * When to use each verification method:
     * - secret: For simple symmetric keys (HS256) - same key signs and verifies
     * - publicKey: For static asymmetric keys (RS256) - private key signs, public verifies
     * - jwksUrl: For providers with key rotation - fetches current public key by kid
     * 
     * JWKS is preferred for production as it:
     * - Supports automatic key rotation
     * - Caches keys to reduce network calls
     * - Rate limits to prevent abuse
     * ----------------------------------------------------------------------- */
    
    /* -----------------------------------------------------------------------
     * NO MORE JWKS CLIENT SETUP - jose handles this internally
     * ----------------------------------------------------------------------- */
    
    /* -----------------------------------------------------------------------
     * TOKEN REVOCATION SETUP
     * 
     * Supports two storage backends:
     * 1. Database: Persistent, survives restarts, scalable
     * 2. Memory: Fast, ephemeral, good for development
     * ----------------------------------------------------------------------- */
    
    if (config.revocation.enabled && config.revocation.storage === 'database') {
      log.info('Setting up token revocation with database storage', {
        tableName: config.revocation.tableName,
        cleanupInterval: config.revocation.cleanupInterval
      });
      // Create the revoked_tokens table if it doesn't exist
      await createRevocationResource(api, config.revocation.tableName, log);
      
      // Set up periodic cleanup of expired tokens
      // This prevents the revocation table from growing indefinitely
      if (config.revocation.cleanupInterval > 0) {
        const cleanupJob = setInterval(async () => {
          try {
            const deleted = await cleanupExpiredTokens(api, config.revocation.tableName, log);
          } catch (error) {
            log.error('Failed to cleanup expired tokens:', error);
          }
        }, config.revocation.cleanupInterval);
        
        // Store cleanup job in state for proper cleanup later
        state.cleanupJob = cleanupJob;
      }
    }
    // Note: In-memory revocation store has limitations:
    // - Tokens are NOT persisted across restarts
    // - No automatic cleanup of expired tokens
    // - Not suitable for multi-instance deployments
    // Use database storage for production systems
    
    addHook('schema:enrich', 'jwt-add-provider-id-fields', {}, async ({ context, scopes }) => {
      const { fields, scopeName } = context;
      
      // Only modify the users resource
      if (scopeName !== config.usersResource) return;
      
      // Add fields for all configured providers
      Object.keys(config.providers).forEach(providerName => {
        const fieldName = `${providerName}_id`;
        
        // Skip if field already exists (e.g., added by provider-specific plugin)
        if (!fields[fieldName]) {
          fields[fieldName] = {
            type: 'string',
            nullable: true,
            unique: true,
            indexed: true,
            description: `User ID from ${providerName} provider`
          };
          log.debug(`Added ${fieldName} field to ${scopeName} resource`);
        }
      });
    });
    
    // HOOK 2: Authenticate incoming requests
    // 
    // WHEN: This hook fires for EVERY incoming HTTP request, very early in the pipeline
    // WHO CALLS IT: The transport plugin (e.g., express-plugin) triggers this hook
    // EXECUTION ORDER: After request parsing but BEFORE any resource operation
    // 
    // DATA FLOW:
    // 1. Transport extracts JWT from Authorization header: "Bearer <token>"
    // 2. Transport sets context.request.token = extracted token string
    // 3. This hook validates the token and populates context.auth
    // 4. All subsequent hooks/operations can access context.auth
    // 
    // FAILURE HANDLING:
    // - No token provided → context.auth = null → request continues as anonymous
    // - Invalid/expired token → context.auth = null → request continues as anonymous
    // - Revoked token → context.auth = null → request continues as anonymous
    // 
    // The request is NEVER blocked here. Instead:
    // - Resources with auth: { query: ['public'] } → Will allow anonymous access
    // - Resources with auth: { query: ['authenticated'] } → Will reject with 403 later
    // 
    // IMPORTANT: This hook ALWAYS returns true (never blocks requests)
    // Authorization happens later in the checkPermissions hook
    addHook('transport:request', 'jwt-populate-auth', {}, async ({ context }) => {
      // Token is extracted by transport layer (e.g., Express plugin)
      const token = context.request.token;
      
      log.trace('JWT authentication hook triggered', {
        hasToken: !!token,
        method: context.method,
        path: context.request?.path
      });
      
      if (!token) {
        // No token provided - this is fine, anonymous access is allowed
        // Individual resources will enforce their own auth requirements
        log.debug('No auth token provided, proceeding as anonymous');
        context.auth = null;
        return true;
      }
      
      // Get the auth provider from request header (X-Auth-Provider)
      // Falls back to default provider if not specified
      const providerName = context.request.headers?.['x-auth-provider'] || 
                          context.request.headers?.['X-Auth-Provider'] || 
                          config.defaultProvider;
      
      log.debug('Determining auth provider', {
        headerProvider: context.request.headers?.['x-auth-provider'] || context.request.headers?.['X-Auth-Provider'],
        defaultProvider: config.defaultProvider,
        selectedProvider: providerName
      });
      
      // Get provider configuration
      const providerConfig = config.providers[providerName];
      
      if (!providerConfig) {
        log.warn(`Unknown auth provider: ${providerName}`, {
          requestedProvider: providerName,
          availableProviders: Object.keys(config.providers)
        });
        context.auth = null;
        return true;
      }
      
      log.trace('Provider configuration found', {
        provider: providerName,
        hasSecret: !!providerConfig.secret,
        hasPublicKey: !!providerConfig.publicKey,
        hasJwksUrl: !!providerConfig.jwksUrl
      });
      
      try {
        log.debug('Verifying JWT token', { provider: providerName });
        
        // Step 1: Verify the token signature and claims using provider-specific config
        const payload = await verifyToken(token, {
          secret: providerConfig.secret,
          publicKey: providerConfig.publicKey,
          algorithms: providerConfig.algorithms,
          audience: providerConfig.audience,
          issuer: providerConfig.issuer,
          jwksUrl: providerConfig.jwksUrl
        }, log);
        
        // Step 2: Check if token has been revoked (logout functionality)
        if (config.revocation.enabled && payload.jti) {
          log.trace('Checking token revocation', { jti: payload.jti });
          const isRevoked = await checkRevocation(
            payload.jti,
            api,
            config.revocation,
            state.memoryRevocationStore,
            log
          );
          
          if (isRevoked) {
            log.info('Token has been revoked', { jti: payload.jti });
            // Token has been revoked - treat as anonymous
            context.auth = null;
            return true;
          }
        }
        
        // Step 3: Get provider-specific user ID from token
        log.trace('JWT AUTH: Token payload:', { payload });
        log.trace('JWT AUTH: Provider config userIdField:', { userIdField: providerConfig.userIdField });
        const providerId = payload[providerConfig.userIdField];
        const email = payload[providerConfig.emailField];
        log.trace('JWT AUTH: Extracted providerId and email', { providerId, email });

        // Step 4: Look up internal user ID from provider ID
        let internalUserId = null;

        if (helpers.jwtAuth && helpers.jwtAuth.getUserByProviderId) {
          try {
            log.trace('Looking up user by provider ID', { providerId, providerName });
            let user = await helpers.jwtAuth.getUserByProviderId(providerId, providerName);
            log.trace('Provider ID lookup result', { userFound: !!user, userId: user?.id });
            
            if (user) {
              internalUserId = user.id;
              log.trace('User found by provider ID, using existing user', { internalUserId });
              log.debug('Found internal user ID from provider ID', {
                providerId,
                internalUserId,
                provider: providerName
              });
            } else {
              log.trace('User not found by provider ID, checking email linking', { 
                autoLinkByEmail: config.autoLinkByEmail, 
                hasEmail: !!email,
                email 
              });
              // User not found by provider ID - check if we should link by email
              if (config.autoLinkByEmail && email) {
                log.trace('Auto-link by email enabled, looking up by email', { email });
                log.debug('Checking for existing user by email', {
                  email,
                  provider: providerName
                });
                
                user = await helpers.jwtAuth.getUserByEmail(email);
                log.trace('Email lookup result', { userFoundByEmail: !!user, userId: user?.id });
                
                if (user) {
                  // Found existing user with same email - link this provider
                  log.trace('Found user by email, will link provider', { 
                    userId: user.id,
                    currentAuth0Id: user.auth0_id,
                    newProviderId: providerId 
                  });
                  log.info('Found existing user with same email, linking provider', {
                    userId: user.id,
                    email: email,
                    newProvider: providerName,
                    newProviderId: providerId
                  });
                  
                  // Update user to add this provider ID
                  try {
                    const providerField = `${providerName}_id`;
                    const updateData = {
                      [providerField]: providerId
                    };
                    log.trace('Preparing to patch user with provider ID', { 
                      userId: user.id,
                      providerField,
                      updateData 
                    });
                    
                    // If this provider provides additional metadata, update it
                    if (payload.user_metadata) {
                      updateData.name = payload.user_metadata.name || user.name;
                      updateData.avatar_url = payload.user_metadata.avatar_url || user.avatar_url;
                      log.trace('Added metadata to update', updateData);
                    }
                    
                    const resource = api.resources[config.usersResource];
                    log.trace('Calling resource.patch to link provider', {
                      id: user.id,
                      ...updateData
                    });
                    await resource.patch({
                      id: user.id,
                      ...updateData
                    }, { auth: { userId: 'system', system: true } });
                    log.trace('Provider linking patch completed successfully');
                    
                    internalUserId = user.id;
                    log.info('Successfully linked provider to existing account', {
                      userId: user.id,
                      email: email,
                      provider: providerName,
                      providerId: providerId
                    });
                  } catch (linkError) {
                    log.error('Failed to link provider to existing user', {
                      error: linkError.message,
                      userId: user.id,
                      provider: providerName
                    });
                    // Still set the internal ID since we found the user
                    internalUserId = user.id;
                  }
                } else {
                }
              } else {
              }
              
              // No existing user found (or auto-link disabled) - create new user
              if (!user) {
                log.info('Creating new user account', {
                  providerId,
                  email,
                  provider: providerName,
                  autoLinkByEmail: config.autoLinkByEmail
                });
                
                // Use provider-specific normalizer to extract user data
                const normalizer = tokenNormalizers[providerName];

                if (!normalizer) {
                  log.error(`No normalizer found for provider '${providerName}'`);
                  throw new Error(`No normalizer found for provider '${providerName}'. Please add a normalizer in jwtAuthNormalizers/${providerName}.js and import it in jwtAuthPlugin.js`);
                }

                const normalized = normalizer(payload);
                const userData = {
                  email: normalized.email,
                  name: normalized.name,
                  avatar_url: normalized.avatar_url
                };
                
                // Auto-sync: Create user in database
                try {
                  const syncedUser = await helpers.jwtAuth.upsertUser(
                    providerId,      // Provider-specific ID
                    userData,        // User data
                    providerName     // Provider name (e.g., 'supabase')
                  );
                  
                  // Handle both simplified and JSON:API response formats
                  const userId = syncedUser?.id || syncedUser?.data?.id;
                  if (userId) {
                    internalUserId = userId;
                    log.info('User auto-synced successfully', {
                      providerId,
                      internalUserId,
                      email,
                      provider: providerName
                    });
                  } else {
                    log.error('Auto-sync returned invalid user data', {
                      providerId,
                      provider: providerName,
                      syncResult: syncedUser
                    });
                  }
                } catch (syncError) {
                  log.error('Failed to auto-sync user', {
                    error: syncError.message,
                    providerId,
                    email,
                    provider: providerName
                  });
                  // Continue without internal ID - user can still access public resources
                }
              }
            }
          } catch (error) {
            log.warn('Failed to lookup/sync user', {
              error: error.message,
              providerId,
              provider: providerName
            });
          }
        }
        
        // Step 5: Populate context.auth with both IDs
        context.auth = {
          userId: internalUserId,                        // Internal database ID (may be null if sync failed)
          providerId: providerId,                        // Provider-specific ID
          email: email,                                  // User email
          provider: providerName,                        // Track which provider authenticated this user
          token: payload,                                // Full token payload for custom use
          tokenId: payload.jti                           // JWT ID for revocation
        };
        
        log.info('JWT authentication successful', {
          userId: context.auth.userId,
          providerId: context.auth.providerId,
          email: context.auth.email,
          provider: providerName,
          hasJti: !!payload.jti,
          exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined
        });
        
        // Step 5: Allow other plugins to react to successful authentication
        context.authPayload = payload;
        await runHooks('afterAuthentication', context);
        
      } catch (error) {
        // Invalid token - log for debugging but treat as anonymous
        // This allows requests to continue with no auth context
        // 
        // Common errors:
        // - TokenExpiredError: JWT has expired (exp claim in past)
        // - JsonWebTokenError: Invalid signature, malformed token
        // - NotBeforeError: Token not active yet (nbf claim in future)
        // 
        // If a token is provided but validation fails, this is an authentication error
        // We should reject the request rather than treating it as unauthenticated
        log.warn('JWT token validation failed', {
          error: error.message,
          errorType: error.name,
          provider: providerName
        });
        
        // Return 401 Unauthorized for invalid tokens
        context.rejection = {
          status: 401,
          title: 'Authentication Failed',
          message: `Invalid token for provider: ${providerName}`
        };
        return false; // Stop processing
      }
      
      // Return true to continue processing
      return true;
    });
    
    /*
     * Summary: Hooks are registered. Every request now:
     * 1. Has its JWT validated and context.auth populated
     * 2. Has its permissions checked against resource auth rules
     * This creates a declarative, centralized auth system.
     * 
     * Example flow with bad token:
     * - Client: POST /api/posts with expired Bearer token
     * - HOOK 2: Token validation fails, sets context.auth = null
     * - REST API: Routes to posts resource, method = 'post'
     * - HOOK 3: Checks posts.auth.post = ['authenticated']
     * - Since context.auth is null, 'authenticated' checker returns false
     * - Result: 403 Forbidden - "Access denied. Required one of: authenticated"
     */
    
    /* -----------------------------------------------------------------------
     * HELPER METHODS
     * 
     * These methods provide programmatic access to JWT-specific functionality.
     * ----------------------------------------------------------------------- */
    
    // Add verifyToken helper for other plugins (like socketio)
    // This allows external plugins to verify JWT tokens using our config
    // Use the default provider's configuration for verification
    helpers.verifyToken = (token) => {
      const providerConfig = config.providers[config.defaultProvider];
      if (!providerConfig) {
        throw new Error(`Default provider '${config.defaultProvider}' not found`);
      }
      return verifyToken(token, providerConfig, log);
    };

    const performLogout = async (context) => {
      log.debug('Logout called with context.auth:', context.auth);

      if (!context.auth?.token) {
        throw new Error('No active session to logout');
      }

      const token = context.auth.token;
      if (!token.jti) {
        throw new Error('Token must have jti claim for revocation');
      }

      if (config.revocation.enabled) {
        if (config.revocation.storage === 'database') {
          try {
            const revokeData = {
              jti: token.jti,
              user_id: context.auth.userId || context.auth.providerId || 'unknown',
              expires_at: new Date(token.exp * 1000),
              revoked_at: new Date()
            };
            log.debug('Attempting to save revoked token', revokeData);
            await api.resources[config.revocation.tableName].post(revokeData);
          } catch (postError) {
            log.error('Failed to save revoked token to database', {
              error: postError.message,
              jti: token.jti,
              userId: context.auth.userId,
              providerId: context.auth.providerId,
              exp: token.exp,
              tableName: config.revocation.tableName,
              authContext: context.auth
            });
            throw postError;
          }
        } else {
          state.memoryRevocationStore.set(token.jti, {
            userId: context.auth.userId,
            expiresAt: token.exp * 1000,
            revokedAt: Date.now()
          });
        }
      }

      context.logoutUserId = context.auth.userId;
      await runHooks('afterLogout', context);

      return { success: true, message: 'Logged out successfully' };
    };

    const revokeToken = async (jti, userId, expiresAt) => {
      if (!config.revocation.enabled) {
        throw new Error('Token revocation is not enabled');
      }

      if (config.revocation.storage === 'database') {
        await api.resources[config.revocation.tableName].post({
          jti,
          user_id: userId,
          expires_at: new Date(expiresAt * 1000),
          revoked_at: new Date()
        });
      } else {
        state.memoryRevocationStore.set(jti, {
          userId,
          expiresAt: expiresAt * 1000,
          revokedAt: Date.now()
        });
      }
    };
    
    /* -----------------------------------------------------------------------
     * END OF HELPER METHODS
     * ----------------------------------------------------------------------- */
    
    /* -----------------------------------------------------------------------
     * JWT AUTH HELPER METHODS FOR USER MANAGEMENT
     * 
     * These helpers provide user management functionality for auth providers.
     * They work with an existing users resource that must be defined separately.
     * ----------------------------------------------------------------------- */
    
    helpers.jwtAuth = {
      /**
       * HELPER: getConfiguredProviders
       * Get list of all configured auth providers
       * Used by auth endpoints to build linked_providers objects
       *
       * @returns {string[]} Array of provider names
       *
       * @example
       * const providers = helpers.jwtAuth.getConfiguredProviders();
       * // Returns: ['google', 'supabase', 'auth0']
       */
      getConfiguredProviders() {
        return Object.keys(config.providers);
      },

      /**
       * HELPER: upsertUser
       * Create or update a user record in the users resource
       * Used by auth providers (Supabase, Google, etc.) to sync user data
       * 
       * @param {string} providerId - Provider-specific user ID
       * @param {object} userData - User attributes to set
       * @param {string} provider - Provider name (e.g., 'supabase', 'google')
       * @returns {Promise<object>} The created or updated user record
       * 
       * @example
       * const user = await helpers.jwtAuth.upsertUser(
       *   '550e8400-e29b-41d4-a716-446655440000',
       *   { email: 'user@example.com', name: 'John Doe' },
       *   'supabase'
       * );
       */
      async upsertUser(providerId, userData, provider = null) {
        log.trace('Upsert user called', { providerId, userData, provider });
        const resource = api.resources[config.usersResource];
        if (!resource) {
          throw new Error(`Users resource '${config.usersResource}' not found. Ensure it's defined in server/api/users.js`);
        }
        
        // First try to find user by provider ID (handles email changes)
        let existing = null;
        if (provider) {
          const providerField = `${provider}_id`;
          log.trace('Looking for existing user by provider field', { providerField, providerId });
          const byProviderId = await resource.query({
            queryParams: {
              filters: { [providerField]: providerId }
            },
          }, { auth: { userId: 'system', system: true } });
          existing = byProviderId.data?.[0];
          log.trace('Provider field query result', { found: !!existing, existingId: existing?.id });

          if (existing && userData.email && existing.email !== userData.email) {
            log.info('User email changed at provider', {
              provider,
              providerId,
              oldEmail: existing.email,
              newEmail: userData.email
            });
            // Will update email in the patch operation below
          }
        }

        // If not found by provider ID, check by email to avoid duplicate email errors
        if (!existing && userData.email) {
          log.trace('Provider ID not found, checking by email', { email: userData.email });
          const byEmail = await resource.query({
            queryParams: {
              filters: { email: userData.email }
            },
          }, { auth: { userId: 'system', system: true } });
          existing = byEmail.data?.[0];
          if (existing) {
            log.debug('Found existing user by email', {
              userId: existing.id,
              email: userData.email,
              provider,
              willAddProviderId: !!provider
            });
          }
        }
        
        
        if (existing) {
          // Update existing user - but NEVER change primary email!
          const updateData = { ...userData };

          // Remove email from update data - primary email is immutable
          delete updateData.email;

          // Store provider-specific email if provider is known
          if (provider && userData.email) {
            updateData[`${provider}_email`] = userData.email;
          }

          if (provider) {
            updateData[`${provider}_id`] = providerId;
          }

          return resource.patch({
            id: existing.id,
            ...updateData
          }, { auth: { userId: existing.id, system: true } });
        } else {
          // Create new user - set both primary email and provider email
          const createData = { ...userData };

          // On creation, also set the provider-specific email
          if (provider && userData.email) {
            createData[`${provider}_email`] = userData.email;
          }

          if (provider) {
            createData[`${provider}_id`] = providerId;
          }
          
          // Since we now check by email upfront, duplicate email errors should be rare
          // Only occurring in true race conditions where two requests create users simultaneously
          try {
            return await resource.post(createData, { auth: { userId: 'system', system: true } });
          } catch (error) {
            // Handle true race condition - if duplicate key error, try to find the user again
            if (error.code === 'ER_DUP_ENTRY' || error.code === '23505' || // MySQL/PostgreSQL
                error.message?.includes('UNIQUE constraint') || // SQLite
                error.message?.includes('duplicate key')) {
              log.info('Race condition detected during user creation, retrying lookup', {
                email: userData.email,
                provider,
                errorCode: error.code
              });

              // Retry finding the user
              if (userData.email) {
                const retryByEmail = await resource.query({
                  queryParams: {
                    filters: { email: userData.email }
                  },
                }, { auth: { userId: 'system', system: true } });
                if (retryByEmail.data?.[0]) {
                  // Update with provider ID if needed - but NOT primary email!
                  const updateData = { ...userData };
                  delete updateData.email;  // Primary email is immutable

                  if (provider && userData.email) {
                    updateData[`${provider}_email`] = userData.email;
                  }
                  if (provider) {
                    updateData[`${provider}_id`] = providerId;
                  }
                  return resource.patch({
                    id: retryByEmail.data[0].id,
                    ...updateData
                  }, { auth: { userId: retryByEmail.data[0].id, system: true } });
                }
              }
            }
            throw error;
          }
        }
      },
      
      /**
       * HELPER: getUser
       * Retrieve a user record from the users resource
       * 
       * @param {string} userId - User ID to retrieve
       * @returns {Promise<object>} The user record
       * 
       * @example
       * const user = await helpers.jwtAuth.getUser('user-123');
       */
      async getUser(userId) {
        const resource = api.resources[config.usersResource];
        if (!resource) {
          throw new Error(`Users resource '${config.usersResource}' not found. Ensure it's defined in server/api/users.js`);
        }
        return resource.get({
          id: userId,
          simplified: true
        }, { auth: { userId: 'system', system: true } });
      },
      
      /**
       * HELPER: getUserByProviderId
       * Retrieve a user record by provider-specific ID
       * 
       * @param {string} providerId - Provider-specific user ID
       * @param {string} provider - Provider name (e.g., 'supabase', 'google')
       * @returns {Promise<object|null>} The user record or null if not found
       * 
       * @example
       * const user = await helpers.jwtAuth.getUserByProviderId(
       *   '550e8400-e29b-41d4-a716-446655440000',
       *   'supabase'
       * );
       */
      async getUserByProviderId(providerId, provider) {
        const resource = api.resources[config.usersResource];
        if (!resource) {
          throw new Error(`Users resource '${config.usersResource}' not found. Ensure it's defined in server/api/users.js`);
        }
        
        const providerField = `${provider}_id`;
        const result = await resource.query({
          queryParams: {
            filters: { [providerField]: providerId }
          },
        }, { auth: { userId: 'system', system: true } });
        
        return result.data?.[0] || null;
      },
      
      /**
       * HELPER: getUserByEmail
       * Retrieve a user record by email address
       * Used for auto-linking accounts with the same email
       * 
       * @param {string} email - The email address to search for
       * @returns {Promise<Object|null>} User record or null if not found
       * 
       * @example
       * const user = await helpers.jwtAuth.getUserByEmail('user@example.com');
       */
      async getUserByEmail(email) {
        const resource = api.resources[config.usersResource];
        if (!resource) {
          throw new Error(`Users resource '${config.usersResource}' not found. Ensure it's defined in server/api/users.js`);
        }
        
        if (!email) {
          return null;
        }
        
        const result = await resource.query({
          queryParams: {
            filters: { email: email }
          },
        }, { auth: { userId: 'system', system: true } });
        
        return result.data?.[0] || null;
      },

      async logout(context) {
        return performLogout(context)
      },

      async revokeToken(jti, userId, expiresAt) {
        return revokeToken(jti, userId, expiresAt)
      },

      cleanup() {
        if (state.cleanupJob) {
          clearInterval(state.cleanupJob)
          state.cleanupJob = null
        }
        state.memoryRevocationStore.clear()
      }
    };
    
    
    /* -----------------------------------------------------------------------
     * OPTIONAL ENDPOINTS
     * 
     * The plugin can automatically create REST endpoints for auth operations.
     * These are opt-in via configuration.
     * ----------------------------------------------------------------------- */

    await api.addRoute({
      method: 'GET',
      path: '/api/auth/me',
      handler: async ({ context }) => {
        // Check if user needs to be synced first
        if (context.auth?.needsSync) {
          return {
            statusCode: 404,
            body: {
              error: 'User not synced',
              message: 'Please sync your user data first',
              needsSync: true,
              providerId: context.auth.providerId,
              provider: context.auth.provider
            }
          };
        }

        if (!context.auth?.userId) {
          return {
            statusCode: 401,
            body: { error: 'Not authenticated' }
          };
        }

        try {
          const user = await helpers.jwtAuth.getUser(context.auth.userId);
          log.info('GET /api/auth/me - Full user object:', JSON.stringify(user, null, 2));

          // In simplified mode, the user object is the data directly
          const userData = user.data || user;

          // Build linked_providers dynamically from configured providers
          const linked_providers = {};
          Object.keys(config.providers).forEach(providerName => {
            const providerIdField = `${providerName}_id`;
            linked_providers[providerName] = userData[providerIdField] || null;
          });

          // Normalize to standard format for consistent API response
          const response = {
            provider: context.auth.provider,
            provider_id: userData[`${context.auth.provider}_id`] || context.auth.providerId,
            linked_providers,
            user: {
              id: String(userData.id),
              email: userData.email,
              email_verified: userData.email_verified !== false,
              name: userData.name,
              avatar_url: userData.avatar_url || userData.picture || userData.google_picture,
              phone: userData.phone || null,
              username: userData.username || null,
              created_at: userData.created_at,
              updated_at: userData.updated_at
            }
          };

          log.info('GET /api/auth/me - Response to return:', JSON.stringify(response, null, 2));

          return {
            statusCode: 200,
            body: response  // Return auth metadata with nested user
          };
        } catch (error) {
          log.error('GET /api/auth/me - Error fetching user:', error);
          return {
            statusCode: 404,
            body: { error: 'User not found' }
          };
        }
      }
    });

    log.info('Added /api/auth/me endpoint');

    /* -----------------------------------------------------------------------
     * OPTIONAL ENDPOINTS
     *
     * The plugin can automatically create REST endpoints for auth operations.
     * These are opt-in via configuration.
     * ----------------------------------------------------------------------- */

    // Add logout endpoint if configured
    if (config.endpoints.logout && api.addRoute) {
      // Add as a public route that checks its own auth
      await api.addRoute({
        method: 'POST',
        path: config.endpoints.logout,
        handler: async ({ context }) => {
          try {
            if (!context.auth) {
              return {
                statusCode: 401,
                body: { error: 'Authentication required' }
              };
            }

            const result = await performLogout(context);
            return { statusCode: 200, body: result };
          } catch (error) {
            return {
              statusCode: 400,
              body: { error: error.message }
            };
          }
        }
      });

      log.info(`Added logout endpoint: POST ${config.endpoints.logout}`);
    }

    // Add session endpoint if configured
    // Returns current user info or {authenticated: false} for anonymous
    if (config.endpoints.session && api.addRoute) {
      await api.addRoute({
        method: 'GET',
        path: config.endpoints.session,
        handler: async ({ context }) => {
          if (!context.auth) {
            return {
              statusCode: 200,
              body: { authenticated: false }
            };
          }

          return {
            statusCode: 200,
            body: {
              authenticated: true,
              user: {
                id: context.auth.userId,
                email: context.auth.email,
                roles: context.auth.roles
              },
              expiresAt: new Date(context.auth.token.exp * 1000).toISOString()
            }
          };
        }
      });

      log.info(`Added session endpoint: GET ${config.endpoints.session}`);
    }
    
    /*
     * Summary: Optional endpoints provide REST API access to auth operations.
     * Enable via config: endpoints: { logout: '/auth/logout', session: '/auth/session' }
     * Always enabled: /auth/me
     */
    
    log.info('JWT authentication plugin installed successfully', {
      providers: Object.keys(config.providers),
      defaultProvider: config.defaultProvider,
      revocation: config.revocation.enabled
    });
  }
};
