/**
 * Google JWT Token Normalizer
 *
 * Shared normalizer for Google authentication tokens.
 * Used by both frontend and backend to ensure consistent data structure.
 *
 * Google JWT structure:
 * - User ID is in `sub` field
 * - Email is in `email` field
 * - Name is in `name` field
 * - Picture is in `picture` field
 */

/**
 * Normalizes a decoded Google JWT token to standard user format
 * @param {Object} decodedToken - The decoded JWT payload (from Google ID token or app JWT)
 * @returns {Object} Normalized user data
 */
export function normalizeGoogleToken(decodedToken) {
  if (!decodedToken) {
    return null;
  }

  // Handle both Google ID tokens and app-generated JWTs
  const isGoogleIdToken = decodedToken.iss?.includes('accounts.google.com');

  if (isGoogleIdToken) {
    // Direct Google ID token
    return {
      // Standard fields
      provider_id: decodedToken.sub,
      email: decodedToken.email || null,
      email_verified: decodedToken.email_verified || false,

      // Profile fields from Google - construct name from parts if needed
      name: decodedToken.name ||
            (decodedToken.given_name && decodedToken.family_name ?
              `${decodedToken.given_name} ${decodedToken.family_name}` :
              decodedToken.given_name ||
              decodedToken.family_name ||
              decodedToken.email?.split('@')[0] ||
              'User'),
      avatar_url: decodedToken.picture || null,
      given_name: decodedToken.given_name || null,
      family_name: decodedToken.family_name || null,

      // Provider info
      provider: 'google',
      is_anonymous: false, // Google doesn't support anonymous

      // Additional Google-specific fields
      locale: decodedToken.locale || null,
      hd: decodedToken.hd || null, // Hosted domain for G Suite

      // Raw token data for provider-specific needs
      raw_metadata: {
        given_name: decodedToken.given_name,
        family_name: decodedToken.family_name,
        locale: decodedToken.locale,
        hd: decodedToken.hd
      }
    };
  } else {
    // App-generated JWT (from our backend)
    return {
      // Standard fields
      provider_id: decodedToken.userId || decodedToken.sub,
      email: decodedToken.email || null,
      email_verified: true, // If we have an app JWT, it was verified

      // Profile fields - these might not be in app JWT
      name: decodedToken.name || decodedToken.email?.split('@')[0] || 'User',
      avatar_url: decodedToken.picture || null,

      // Provider info
      provider: decodedToken.provider || 'google',
      is_anonymous: false,

      // Empty metadata for app JWTs
      raw_metadata: {}
    };
  }
}

/**
 * Normalizes a Google session object (frontend use)
 *
 * For Google, the backend already returns a fully normalized session
 * in the exact format the app expects. No transformation needed.
 *
 * @param {Object} session - The session object from Google auth backend
 * @returns {Object} The session unchanged (already normalized by backend)
 */
export function normalizeGoogleSession(session) {
  // The backend (/api/auth/google/one-tap) already returns:
  // - Standardized session structure
  // - Normalized user object with linked_providers
  // - All fields in the correct format
  //
  // Just return it as-is
  return session;
}