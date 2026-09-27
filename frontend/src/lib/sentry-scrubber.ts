/**
 * Frontend Sentry Scrubber
 * 
 * This is a thin wrapper that re-exports the shared scrubber implementation.
 * The actual scrubbing logic lives in packages/sentry-scrubber to ensure
 * frontend and backend use identical security filtering.
 */

export { scrubEvent, scrubString, scrub, isSensitiveKey } from '@pulsartrack/sentry-scrubber';
