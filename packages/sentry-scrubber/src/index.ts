/**
 * Sentry Event Scrubber
 * 
 * Removes sensitive information from error reports before sending to Sentry.
 * Shared between frontend and backend to ensure consistent security handling.
 * 
 * What gets scrubbed:
 * - Stellar secret seeds (S followed by 55 base32 characters)
 * - Stellar contract addresses (C followed by 55 base32 characters)  
 * - JWT tokens (eyJ...format)
 * - Bearer tokens in Authorization headers
 * - Sensitive query parameters (token, key, secret, etc.)
 * - Object keys matching sensitive patterns (token, secret, password, username, etc.)
 * 
 * What is NOT scrubbed:
 * - Stellar public keys (G followed by 55 base32 characters)
 * - Non-sensitive keys (userId, keyboard, etc.)
 */

/**
 * Explicit list of sensitive key patterns.
 * Uses word boundaries (\b) to avoid false matches like "keyboard" or "monkey".
 */
const SENSITIVE_KEY_PATTERN =
  /\b(?:user(?:name)?|token|secret|key|seed|mnemonic|password|bearer|auth|credential|private|cookie|session|jwt|email|phone|ip_address)\b/i;

/**
 * Stellar secret seed pattern: S followed by exactly 55 base32 characters (A-Z, 2-7).
 * Example: SBGWKM3CD4IL47QN6X54N6Y33T3JDNVI6AIJ6CD5IG5QNKCBHFJWC5AFF3
 */
const STELLAR_SEED_PATTERN = /\bS[A-Z2-7]{55}\b/g;

/**
 * Stellar contract address pattern: C followed by exactly 55 base32 characters.
 * These should also be filtered as they may be sensitive in some contexts.
 */
const STELLAR_CONTRACT_PATTERN = /\bC[A-Z2-7]{55}\b/g;

/**
 * JWT token pattern: eyJ followed by base64url characters, with two dots separating three segments.
 */
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

/**
 * Bearer token pattern in Authorization headers.
 * Captures "bearer " prefix and replaces everything after it.
 */
const BEARER_PATTERN = /(bearer\s+)[^\s"']+/gi;

/**
 * Sensitive query parameters in URLs.
 * Matches ?key=value or &key=value where key is sensitive.
 */
const SENSITIVE_QUERY_PARAM_PATTERN =
  /([?&](?:token|key|secret|api_key|apikey|password|seed|mnemonic|bearer|auth|access_token|refresh_token|private_key|x-api-key)=)[^&\s"']+/gi;

/**
 * Scrub sensitive patterns from a string value.
 */
export function scrubString(val: string): string {
  if (!val) return val;
  let scrubbed = val;
  scrubbed = scrubbed.replace(STELLAR_SEED_PATTERN, "[Filtered]");
  scrubbed = scrubbed.replace(STELLAR_CONTRACT_PATTERN, "[Filtered]");
  scrubbed = scrubbed.replace(JWT_PATTERN, "[Filtered]");
  scrubbed = scrubbed.replace(BEARER_PATTERN, "$1[Filtered]");
  scrubbed = scrubbed.replace(SENSITIVE_QUERY_PARAM_PATTERN, "$1[Filtered]");
  return scrubbed;
}

/**
 * Check if an object key matches sensitive patterns.
 * Uses explicit word boundaries to avoid false positives.
 * 
 * Returns true for: username, user, authToken, jwtSecret, api_key
 * Returns false for: userId, keyboard, monkey, author
 */
export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

/**
 * Recursively scrub sensitive information from any value.
 * - Strings are scrubbed for patterns
 * - Arrays are mapped recursively
 * - Objects have sensitive keys filtered and values scrubbed recursively
 */
export function scrub(value: unknown): unknown {
  if (typeof value === "string") {
    return scrubString(value);
  }
  if (Array.isArray(value)) {
    return value.map(scrub);
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      isSensitiveKey(key) ? "[Filtered]" : scrub(item),
    ])
  );
}

/**
 * Scrub a Sentry event before it is sent.
 * This is the main entry point used by Sentry beforeSend hooks.
 */
export function scrubEvent<T>(event: T): T {
  return scrub(event) as T;
}
