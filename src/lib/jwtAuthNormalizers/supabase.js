/**
 * Supabase JWT Token Normalizer
 *
 * Shared normalizer for Supabase authentication tokens.
 * Used by both frontend and backend to ensure consistent data structure.
 *
 * Supabase JWT structure:
 * - User metadata is in `raw_user_meta_data` field in the JWT
 * - User ID is in `sub` field
 * - Email is in `email` field
 */

/**
 * Normalizes a decoded Supabase JWT token to standard user format
 * @param {Object} decodedToken - The decoded JWT payload
 * @returns {Object} Normalized user data
 */
export function normalizeSupabaseToken(decodedToken) {
  if (!decodedToken) {
    return null;
  }

  // Extract metadata from Supabase's structure
  const metadata = decodedToken.raw_user_meta_data || decodedToken.user_metadata || {};

  return {
    // Standard fields
    email: decodedToken.email || null,
    email_verified: decodedToken.email_verified || false,

    // Profile fields - normalize from various possible locations
    name: metadata.full_name ||
          metadata.name ||
          metadata.display_name ||
          decodedToken.name ||
          (decodedToken.email ? decodedToken.email.split('@')[0] : 'User'),

    avatar_url: metadata.avatar_url ||
                metadata.picture ||
                metadata.profile_picture ||
                decodedToken.picture ||
                null,

    // Additional metadata that might be useful
    phone: decodedToken.phone || null,
    is_anonymous: decodedToken.is_anonymous || false,
    role: decodedToken.role || 'authenticated',

    // Keep the raw metadata for provider-specific needs
    raw_metadata: metadata
  };
}

/**
 * Normalizes a Supabase session object (frontend use)
 * @param {Object} session - The Supabase session object
 * @returns {Object} Normalized session
 */
export function normalizeSupabaseSession(session) {
  if (!session) {
    return null;
  }

  // Decode the JWT without verification (frontend can't verify)
  let decodedToken = null;
  try {
    const base64Payload = session.access_token.split('.')[1];
    const payload = atob(base64Payload.replace(/-/g, '+').replace(/_/g, '/'));
    decodedToken = JSON.parse(payload);
  } catch (error) {
    console.error('Failed to decode Supabase token:', error);
    // Fall back to using session.user data
  }

  // If we have a decoded token, use it for normalization
  // Otherwise, try to normalize from session.user
  let normalizedUser;

  if (decodedToken) {
    normalizedUser = normalizeSupabaseToken(decodedToken);
  } else if (session.user) {
    // Fallback: normalize from session.user object
    const user = session.user;
    const metadata = user.user_metadata || {};

    normalizedUser = {
      email: user.email,
      email_verified: user.email_verified || false,
      name: metadata.full_name || metadata.name || user.email?.split('@')[0] || 'User',
      avatar_url: metadata.avatar_url || metadata.picture || null,
      is_anonymous: user.is_anonymous || false,
      phone: user.phone || null,
      role: user.role || 'authenticated',
      created_at: user.created_at,
      updated_at: user.updated_at
    };
  }

  return {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    expires_in: session.expires_in,
    token_type: session.token_type || 'Bearer',
    provider: 'supabase',
    provider_id: decodedToken?.sub || session.user?.id,  // Provider ID at root level
    user: normalizedUser,
    is_anonymous: normalizedUser?.is_anonymous || false
  };
}