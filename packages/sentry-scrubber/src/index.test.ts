import { describe, expect, it, beforeAll } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import { isSensitiveKey, scrubEvent, scrubString } from "./index";

// Generate real Stellar keypairs for testing
let testKeypair: Keypair;
let testSeed: string;
let testPublicKey: string;

beforeAll(() => {
  testKeypair = Keypair.random();
  testSeed = testKeypair.secret();
  testPublicKey = testKeypair.publicKey();
});

describe("Sentry Scrubber - Sensitive Key Detection", () => {
  describe("should recognize sensitive keys (return true)", () => {
    const sensitiveKeys = [
      "username",
      "user",
      "authToken",
      "jwtSecret",
      "secret_key",
      "private_key",
      "seed",
      "userMnemonic",
      "password",
      "x-api-key",
      "bearer",
      "session_id",
      "email",
      "phone",
      "ip_address",
      "auth",
      "credential",
      "cookie",
      "jwt",
    ];

    sensitiveKeys.forEach((key) => {
      it(`should mark "${key}" as sensitive`, () => {
        expect(isSensitiveKey(key)).toBe(true);
      });
    });
  });

  describe("should NOT recognize non-sensitive keys (return false)", () => {
    const nonSensitiveKeys = [
      "userId",        // Contains "user" but as part of compound word
      "keyboard",      // Contains "key" but not a match
      "monkey",        // Contains "key" but not a match  
      "author",        // Contains "auth" but not a match
      "data",
      "value",
      "config",
      "settings",
      "metadata",
    ];

    nonSensitiveKeys.forEach((key) => {
      it(`should NOT mark "${key}" as sensitive`, () => {
        expect(isSensitiveKey(key)).toBe(false);
      });
    });
  });
});

describe("Sentry Scrubber - String Scrubbing", () => {
  it("should scrub real Stellar secret seeds", () => {
    const input = `Error failed with seed ${testSeed} on network`;
    const result = scrubString(input);
    expect(result).toBe("Error failed with seed [Filtered] on network");
    expect(result).not.toContain(testSeed);
  });

  it("should NOT scrub Stellar public keys (G...)", () => {
    const input = `Transaction from ${testPublicKey} succeeded`;
    const result = scrubString(input);
    expect(result).toBe(input);
    expect(result).toContain(testPublicKey);
  });

  it("should scrub Stellar contract addresses (C...)", () => {
    // Generate a contract address (C followed by 55 base32 characters)
    const contractId = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const input = `Contract ${contractId} deployed`;
    const result = scrubString(input);
    expect(result).toBe("Contract [Filtered] deployed");
  });

  it("should scrub JWT tokens", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const input = `User token is ${jwt}`;
    const result = scrubString(input);
    expect(result).toBe("User token is [Filtered]");
  });

  it("should scrub Bearer credentials", () => {
    const input = "Authorization header: Bearer mySecretToken123";
    const result = scrubString(input);
    expect(result).toBe("Authorization header: Bearer [Filtered]");
  });

  it("should scrub sensitive query parameters in URLs", () => {
    const url =
      "https://api.pulsartrack.com/v1/data?token=secret123&key=abc456&public=true";
    const result = scrubString(url);
    expect(result).toBe(
      "https://api.pulsartrack.com/v1/data?token=[Filtered]&key=[Filtered]&public=true"
    );
  });

  it("should scrub multiple patterns in one string", () => {
    const input = `Error: seed ${testSeed} with token eyJhbGc.payload.sig and Bearer abc123`;
    const result = scrubString(input);
    expect(result).not.toContain(testSeed);
    expect(result).toContain("[Filtered]");
    expect(result).toContain("Bearer [Filtered]");
  });
});

describe("Sentry Scrubber - Event Scrubbing", () => {
  it("should scrub nested Sentry events with real seeds and sensitive keys", () => {
    const event = {
      exception: {
        values: [
          {
            type: "Error",
            value: `Critical failure using seed ${testSeed} during transaction`,
          },
        ],
      },
      request: {
        url: "https://api.pulsartrack.com/pay?token=secretTokenValue&amount=10",
      },
      breadcrumbs: [
        {
          message: "Sending header Bearer topSecretToken",
        },
      ],
      extra: {
        jwtSecret: "unscrubbedSecretValue",
        username: "alice",
        userId: "user_12345",  // Should NOT be scrubbed (not a sensitive key)
        safeValue: 12345,
      },
      user: {
        email: "test@example.com",
        id: "12345",
      },
    };

    const scrubbed = scrubEvent(event);

    // Verify seed is scrubbed
    expect(scrubbed.exception.values[0].value).toBe(
      "Critical failure using seed [Filtered] during transaction"
    );
    expect(scrubbed.exception.values[0].value).not.toContain(testSeed);

    // Verify URL query params are scrubbed
    expect(scrubbed.request.url).toBe(
      "https://api.pulsartrack.com/pay?token=[Filtered]&amount=10"
    );

    // Verify Bearer token is scrubbed
    expect(scrubbed.breadcrumbs[0].message).toBe("Sending header Bearer [Filtered]");

    // Verify sensitive keys are scrubbed
    expect(scrubbed.extra.jwtSecret).toBe("[Filtered]");
    expect(scrubbed.extra.username).toBe("[Filtered]");
    expect(scrubbed.user.email).toBe("[Filtered]");

    // Verify non-sensitive values are preserved
    expect(scrubbed.extra.userId).toBe("user_12345");
    expect(scrubbed.extra.safeValue).toBe(12345);
    expect(scrubbed.user.id).toBe("12345");
  });

  it("should handle arrays with sensitive data", () => {
    const event = {
      breadcrumbs: [
        { message: `Seed: ${testSeed}` },
        { message: "Safe message" },
        { message: "Bearer secretToken" },
      ],
    };

    const scrubbed = scrubEvent(event);
    expect(scrubbed.breadcrumbs[0].message).toBe("Seed: [Filtered]");
    expect(scrubbed.breadcrumbs[1].message).toBe("Safe message");
    expect(scrubbed.breadcrumbs[2].message).toBe("Bearer [Filtered]");
  });

  it("should preserve Stellar public keys in events", () => {
    const event = {
      extra: {
        publicKey: testPublicKey,
        fromAccount: testPublicKey,
      },
    };

    const scrubbed = scrubEvent(event);
    expect(scrubbed.extra.publicKey).toBe(testPublicKey);
    expect(scrubbed.extra.fromAccount).toBe(testPublicKey);
  });
});

describe("Sentry Scrubber - Edge Cases", () => {
  it("should handle null and undefined values", () => {
    expect(scrubString(null as any)).toBe(null);
    expect(scrubString(undefined as any)).toBe(undefined);
    expect(scrubString("")).toBe("");
  });

  it("should handle non-string, non-object values", () => {
    expect(scrubEvent(12345)).toBe(12345);
    expect(scrubEvent(true)).toBe(true);
    expect(scrubEvent(null)).toBe(null);
  });

  it("should handle deeply nested objects", () => {
    const event = {
      level1: {
        level2: {
          level3: {
            secret: "should-be-filtered",
            safe: "should-remain",
          },
        },
      },
    };

    const scrubbed = scrubEvent(event);
    expect(scrubbed.level1.level2.level3.secret).toBe("[Filtered]");
    expect(scrubbed.level1.level2.level3.safe).toBe("should-remain");
  });
});
