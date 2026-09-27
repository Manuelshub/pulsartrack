import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest';
import { createJwt, decodeJwt, InvalidTokenError, TOKEN_EXPIRY } from '../lib/jwt';

// Mock logger to suppress output
vi.mock('../lib/logger', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() },
}));

// Mock Redis to avoid real connections
vi.mock('../config/redis', () => ({
  default: {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue('OK'),
    del: vi.fn().mockResolvedValue(1),
    incr: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(1),
    disconnect: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock database to avoid real connections
vi.mock('../config/database', () => ({
  query: vi.fn().mockResolvedValue({ rows: [] }),
  pool: {
    query: vi.fn().mockResolvedValue({ rows: [] }),
    end: vi.fn().mockResolvedValue(undefined),
  },
}));

describe('JWT (jwt.ts)', () => {
  it('should create and decode a valid JWT', () => {
    const payload = { sub: 'GABC123' };
    const token = createJwt(payload);
    const decoded = decodeJwt(token);
    expect(decoded.sub).toBe('GABC123');
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBe(decoded.iat + TOKEN_EXPIRY);
  });

  it('should reject a tampered token (invalid signature)', () => {
    const token = createJwt({ sub: 'GABC123' });
    const parts = token.split('.');
    parts[1] = Buffer.from(JSON.stringify({ sub: 'GFAKE', iat: 0, exp: 999999999 })).toString('base64url');
    const tampered = parts.join('.');
    expect(() => decodeJwt(tampered)).toThrow(InvalidTokenError);
    expect(() => decodeJwt(tampered)).toThrow('Invalid token signature');
  });

  describe('should reject malformed tokens with InvalidTokenError (not SyntaxError)', () => {
    it('should reject token with wrong segment count', () => {
      expect(() => decodeJwt('onlytwosegments.here')).toThrow(InvalidTokenError);
      expect(() => decodeJwt('')).toThrow(InvalidTokenError);
    });

    it('should reject token with invalid base64', () => {
      expect(() => decodeJwt('not.a.jwt')).toThrow(InvalidTokenError);
      expect(() => decodeJwt('not.a.jwt')).toThrow('Invalid token signature');
    });

    it('should reject validly signed token with non-JSON header', () => {
      const header = Buffer.from('not-json').toString('base64url');
      const body = Buffer.from(JSON.stringify({ sub: 'GABC', iat: 0, exp: 999999999999 })).toString('base64url');
      const crypto = require('crypto');
      const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'test').update(`${header}.${body}`).digest('base64url');
      const malformedToken = `${header}.${body}.${sig}`;
      expect(() => decodeJwt(malformedToken)).toThrow(InvalidTokenError);
      expect(() => decodeJwt(malformedToken)).toThrow('Invalid token header');
    });

    it('should reject validly signed token with non-JSON payload', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from('not-json').toString('base64url');
      const crypto = require('crypto');
      const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'test').update(`${header}.${body}`).digest('base64url');
      const malformedToken = `${header}.${body}.${sig}`;
      expect(() => decodeJwt(malformedToken)).toThrow(InvalidTokenError);
      expect(() => decodeJwt(malformedToken)).toThrow('Invalid token payload');
    });

    it('should reject token with wrong algorithm', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS512', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from(JSON.stringify({ sub: 'GABC', iat: 0, exp: 999999999999 })).toString('base64url');
      const crypto = require('crypto');
      const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'test').update(`${header}.${body}`).digest('base64url');
      const wrongAlgToken = `${header}.${body}.${sig}`;
      expect(() => decodeJwt(wrongAlgToken)).toThrow(InvalidTokenError);
      expect(() => decodeJwt(wrongAlgToken)).toThrow('Invalid token header');
    });
  });

  it('should reject an expired token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({ sub: 'GABC', iat: 0, exp: 1 })).toString('base64url');
    const crypto = require('crypto');
    const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'test').update(`${header}.${body}`).digest('base64url');
    const expiredToken = `${header}.${body}.${sig}`;
    expect(() => decodeJwt(expiredToken)).toThrow(InvalidTokenError);
    expect(() => decodeJwt(expiredToken)).toThrow('Token expired');
  });
});

describe('requireAuth middleware', () => {
  let app: any;
  let request: any;

  // Import app once before all tests (not in each test)
  beforeAll(async () => {
    const appModule = await import('../app');
    app = appModule.default;
    request = (await import('supertest')).default;
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should reject request with no Authorization header', async () => {
    // /api/contracts uses requireAuth
    const res = await request(app).get('/api/contracts');
    expect(res.status).toBe(401);
  });

  it('should reject request with invalid token', async () => {
    const res = await request(app)
      .get('/api/contracts')
      .set('Authorization', 'Bearer invalid.token.here');
    expect(res.status).toBe(401);
  });

  it('should reject request with expired token', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({ sub: 'GABC', iat: 0, exp: 1 })).toString('base64url');
    const crypto = require('crypto');
    const jwtSecret = process.env.JWT_SECRET || 'test';
    const sig = crypto.createHmac('sha256', jwtSecret).update(`${header}.${body}`).digest('base64url');
    const expiredToken = `${header}.${body}.${sig}`;
    const res = await request(app)
      .get('/api/contracts')
      .set('Authorization', `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/expired/i);
  });

  it('should accept request with valid token', async () => {
    const token = createJwt({ sub: 'GA4LYCAMDLLOJPGXHQCHHPXBISH5RAWSS7ZTCSQAPKASBXG4NTB5MJ6N' });
    const res = await request(app)
      .get('/api/contracts')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.contracts).toBeDefined();
  });
});
