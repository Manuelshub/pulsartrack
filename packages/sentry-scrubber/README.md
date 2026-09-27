# @pulsartrack/sentry-scrubber

Shared Sentry event scrubber for PulsarTrack frontend and backend.

## Purpose

This package ensures consistent security filtering of sensitive information before error reports reach Sentry. By centralizing the scrubbing logic, we guarantee that frontend and backend handle secrets identically.

## What Gets Scrubbed

### String Patterns
- **Stellar secret seeds**: `S` followed by 55 base32 characters (A-Z, 2-7)
- **Stellar contract IDs**: `C` followed by 55 base32 characters
- **JWT tokens**: `eyJ...` format
- **Bearer tokens**: In Authorization headers
- **Sensitive URL parameters**: token, key, secret, api_key, password, etc.

### Object Keys
Keys matching these patterns (with word boundaries):
- `username` or `user`
- `token`, `secret`, `key`, `seed`
- `mnemonic`, `password`, `bearer`
- `auth`, `credential`, `private`
- `cookie`, `session`, `jwt`
- `email`, `phone`, `ip_address`

## What Is NOT Scrubbed

- **Stellar public keys**: `G` followed by 55 characters (safe to log)
- **Non-sensitive keys**: `userId`, `keyboard`, `author` (no word boundary match)

## Usage

```typescript
import { scrubEvent, scrubString, isSensitiveKey } from '@pulsartrack/sentry-scrubber';

// In Sentry config
Sentry.init({
  beforeSend: (event) => scrubEvent(event),
});

// Manual scrubbing
const safe = scrubString('Error with seed SBGWKM3CD4IL47QN6...');
// => 'Error with seed [Filtered]'

// Check if a key is sensitive
isSensitiveKey('authToken')  // => true
isSensitiveKey('userId')     // => false
```

## Development

```bash
npm install
npm run build
npm test
```

## Testing

Tests use **real Stellar keypairs** generated with `@stellar/stellar-sdk` to ensure patterns match actual secret keys, not fake test data.

## Integration

Both `frontend/src/lib/sentry-scrubber.ts` and `backend/src/lib/sentry-scrubber.ts` are thin wrappers that re-export this shared implementation.
