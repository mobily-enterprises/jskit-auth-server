import { jwtVerify, decodeProtectedHeader, decodeJwt, createRemoteJWKSet, importSPKI } from 'jose';

/**
 * Verify JWT token with multiple strategies using jose
 */
export async function verifyToken(token, options, log) {
  const { secret, publicKey, algorithms, audience, issuer, jwksUrl } = options;
  
  // Use provided logger or create a simple console logger
  const logger = log || {
    trace: (...args) => console.log('[TRACE]', ...args),
    debug: (...args) => console.log('[DEBUG]', ...args),
    info: (...args) => console.log('[INFO]', ...args),
    warn: (...args) => console.warn('[WARN]', ...args),
    error: (...args) => console.error('[ERROR]', ...args)
  };
  
  logger.trace('JWT token verification started', {
    method: jwksUrl ? 'JWKS' : publicKey ? 'PublicKey' : secret ? 'Secret' : 'None',
    hasSecret: !!secret,
    hasPublicKey: !!publicKey,
    hasJwksUrl: !!jwksUrl,
    algorithms
  });
  
  // Decode token header to get kid if needed
  const header = decodeProtectedHeader(token);
  logger.trace('Token header decoded', {
    alg: header.alg,
    typ: header.typ,
    kid: header.kid
  });
  
  // Prepare verification options
  const verifyOptions = {};
  if (algorithms) verifyOptions.algorithms = algorithms;
  if (audience) verifyOptions.audience = audience;
  if (issuer) verifyOptions.issuer = issuer;
  
  try {
    let result;
    
    if (jwksUrl) {
      // Use JWKS URL with jose's built-in support
      const JWKS = createRemoteJWKSet(new URL(jwksUrl), {
        cacheMaxAge: 600000, // 10 minutes cache
        cooldownDuration: 30000 // 30 seconds cooldown on errors
      });
      
      result = await jwtVerify(token, JWKS, verifyOptions);
    } else if (publicKey) {
      // Import public key
      const key = await importSPKI(publicKey, algorithms?.[0] || 'RS256');
      result = await jwtVerify(token, key, verifyOptions);
    } else if (secret) {
      // Use secret for symmetric algorithms
      const encoder = new TextEncoder();
      const key = encoder.encode(secret);
      result = await jwtVerify(token, key, verifyOptions);
    } else {
      throw new Error('No signing key available');
    }
    
    // Return the payload (jose returns {payload, protectedHeader})
    logger.debug('JWT token verified successfully', {
      sub: result.payload.sub,
      email: result.payload.email,
      iat: result.payload.iat ? new Date(result.payload.iat * 1000).toISOString() : undefined,
      exp: result.payload.exp ? new Date(result.payload.exp * 1000).toISOString() : undefined,
      jti: result.payload.jti
    });
    return result.payload;
  } catch (error) {
    logger.warn('JWT token verification failed', {
      error: error.message,
      code: error.code,
      claim: error.claim
    });
    // Map jose errors to match existing error handling
    if (error.code === 'ERR_JWT_EXPIRED') {
      const expiredError = new Error('jwt expired');
      expiredError.name = 'TokenExpiredError';
      throw expiredError;
    }
    if (error.code === 'ERR_JWS_INVALID' || error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      const invalidError = new Error('invalid signature');
      invalidError.name = 'JsonWebTokenError';
      throw invalidError;
    }
    if (error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
      const validationError = new Error(error.message);
      validationError.name = 'JsonWebTokenError';
      throw validationError;
    }
    throw error;
  }
}

/**
 * Decode JWT without verification (for getting header/payload info)
 */
export function decodeToken(token, options = {}) {
  try {
    if (options.complete) {
      return {
        header: decodeProtectedHeader(token),
        payload: decodeJwt(token)
      };
    }
    return decodeJwt(token);
  } catch (error) {
    return null;
  }
}

/**
 * Create the revoked tokens resource
 */
export async function createRevocationResource(api, tableName, log) {
  const logger = log || { 
    info: (...args) => console.log('[INFO]', ...args),
    debug: (...args) => console.log('[DEBUG]', ...args)
  };
  
  // Check if resource already exists
  if (api.resources[tableName]) {
    logger.debug(`Revocation resource '${tableName}' already exists`);
    return;
  }
  
  logger.info(`Creating revocation resource: ${tableName}`);
  
  await api.addResource(tableName, {
    schema: {
      id: { type: 'id' },
      jti: { type: 'string', required: true, unique: true },
      user_id: { type: 'string', required: true },
      expires_at: { type: 'dateTime', required: true },
      revoked_at: { type: 'dateTime', required: true }
    },
    
    // Add index for cleanup queries
    indexes: [
      { fields: ['expires_at'] },
      { fields: ['user_id'] }
    ],
    
    // Hide from API discovery
    hidden: true
  });
}

/**
 * Check if token is revoked
 */
export async function checkRevocation(jti, api, config, memoryStore, log) {
  const logger = log || {
    trace: (...args) => console.log('[TRACE]', ...args),
    debug: (...args) => console.log('[DEBUG]', ...args)
  };
  
  logger.trace('Checking token revocation', { jti, storage: config.storage });
  
  if (config.storage === 'database') {
    try {
      const result = await api.resources[config.tableName].get({
        id: jti,
        simplified: true
      });
      logger.debug('Token found in revocation list', { jti });
      return !!result;
    } catch (error) {
      // Not found = not revoked
      if (error.subtype === 'not_found') {
        logger.trace('Token not in revocation list', { jti });
        return false;
      }
      logger.error('Error checking token revocation', { jti, error: error.message });
      throw error;
    }
  } else {
    // Memory storage - also clean up expired tokens while we're here
    const now = Date.now();
    let cleanedCount = 0;
    for (const [storedJti, data] of memoryStore.entries()) {
      if (data.expiresAt < now) {
        memoryStore.delete(storedJti);
        cleanedCount++;
      }
    }
    
    if (cleanedCount > 0) {
      logger.trace(`Cleaned ${cleanedCount} expired tokens from memory store`);
    }
    
    const isRevoked = memoryStore.has(jti);
    logger.trace(`Token revocation check result`, { jti, isRevoked });
    return isRevoked;
  }
}

/**
 * Clean up expired tokens from revocation table
 */
export async function cleanupExpiredTokens(api, tableName, log) {
  const logger = log || {
    debug: (...args) => console.log('[DEBUG]', ...args),
    error: (...args) => console.error('[ERROR]', ...args)
  };
  
  const knex = api.knex || api.vars?.knex;
  
  if (!knex) {
    logger.error('Knex instance not found for cleanup');
    throw new Error('Knex instance not found for cleanup');
  }
  
  const result = await knex(tableName)
    .where('expires_at', '<', new Date())
    .delete();
  
  if (result > 0) {
    logger.debug(`Cleaned up ${result} expired tokens from ${tableName}`);
  }
  
  return result;
}
