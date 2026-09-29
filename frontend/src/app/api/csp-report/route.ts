import { NextRequest, NextResponse } from "next/server";

/**
 * CSP violation report endpoint.
 *
 * Browsers POST here via the `report-uri` directive (legacy format) or the
 * `report-to` / Reporting API (modern format). Both formats are parsed.
 *
 * Security controls:
 *  - 10 KB body size limit — rejects oversized payloads before parsing.
 *  - Content-Type allowlist — only accepts the three media types used by
 *    browsers for CSP reports; everything else gets 415.
 *  - Per-IP rate limiting (60 requests per minute) — mitigates log-flooding
 *    from a single source.
 *  - Each logged field is truncated to 200 characters before it reaches the
 *    logger, preventing log injection through arbitrarily long URIs.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 * @see https://www.w3.org/TR/reporting/
 */

const MAX_BODY_BYTES = 10 * 1024; // 10 KB
const MAX_FIELD_LEN = 200;

/** Accepted Content-Type values for CSP/Reporting API posts. */
const ACCEPTED_CONTENT_TYPES = new Set([
  "application/csp-report",
  "application/reports+json",
  "application/json",
]);

/** In-memory rate limiter: IP → { count, windowStart } */
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 60; // 60 requests per minute per IP

function getClientIp(request: NextRequest): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX) {
    return true;
  }
  return false;
}

/** Truncate a field value to a safe maximum length. */
function trunc(value: unknown): string {
  if (value == null) return "";
  const str = String(value);
  return str.length > MAX_FIELD_LEN ? str.slice(0, MAX_FIELD_LEN) + "…" : str;
}

interface NormalizedReport {
  documentUri: string;
  violatedDirective: string;
  blockedUri: string;
  sourceFile: string;
  lineNumber: string;
  format: "legacy" | "reporting-api";
}

/**
 * Parse both the legacy `csp-report` format and the modern Reporting API
 * array format (`[{ type: "csp-violation", body: {...} }]`).
 */
function parseReport(payload: unknown): NormalizedReport[] {
  if (Array.isArray(payload)) {
    // Modern Reporting API: array of { type, age, url, body }
    return payload
      .filter(
        (item): item is Record<string, unknown> =>
          typeof item === "object" && item !== null,
      )
      .map((item) => {
        const body =
          typeof item.body === "object" && item.body !== null
            ? (item.body as Record<string, unknown>)
            : {};
        return {
          documentUri: trunc(item.url ?? body["documentURL"] ?? body["document-uri"]),
          violatedDirective: trunc(
            body["effectiveDirective"] ?? body["violated-directive"],
          ),
          blockedUri: trunc(body["blockedURL"] ?? body["blocked-uri"]),
          sourceFile: trunc(body["sourceFile"] ?? body["source-file"]),
          lineNumber: trunc(body["lineNumber"] ?? body["line-number"]),
          format: "reporting-api" as const,
        };
      });
  }

  if (typeof payload === "object" && payload !== null) {
    const report = payload as Record<string, unknown>;
    // Legacy format: { "csp-report": { ... } } or the inner object directly
    const inner =
      typeof report["csp-report"] === "object" && report["csp-report"] !== null
        ? (report["csp-report"] as Record<string, unknown>)
        : report;
    return [
      {
        documentUri: trunc(inner["document-uri"]),
        violatedDirective: trunc(inner["violated-directive"]),
        blockedUri: trunc(inner["blocked-uri"]),
        sourceFile: trunc(inner["source-file"]),
        lineNumber: trunc(inner["line-number"]),
        format: "legacy" as const,
      },
    ];
  }

  return [];
}

export async function POST(request: NextRequest) {
  // ── Content-Type check ──────────────────────────────────────────────────
  const contentType = request.headers.get("content-type")?.split(";")[0]?.trim() ?? "";
  if (!ACCEPTED_CONTENT_TYPES.has(contentType)) {
    return new NextResponse(null, { status: 415 });
  }

  // ── Body size limit ─────────────────────────────────────────────────────
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 });
  }

  // ── Rate limiting ───────────────────────────────────────────────────────
  const ip = getClientIp(request);
  if (isRateLimited(ip)) {
    return new NextResponse(null, { status: 429 });
  }

  try {
    // Read at most MAX_BODY_BYTES to guard against missing Content-Length.
    const reader = request.body?.getReader();
    if (!reader) {
      return new NextResponse(null, { status: 204 });
    }
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        reader.cancel();
        return new NextResponse(null, { status: 413 });
      }
      chunks.push(value);
    }
    const body = new TextDecoder().decode(
      chunks.reduce((acc, chunk) => {
        const merged = new Uint8Array(acc.length + chunk.length);
        merged.set(acc);
        merged.set(chunk, acc.length);
        return merged;
      }, new Uint8Array(0)),
    );

    const payload: unknown = JSON.parse(body);
    const reports = parseReport(payload);

    for (const report of reports) {
      console.warn(
        "[CSP-VIOLATION]",
        JSON.stringify({ ...report, ip }),
      );
    }
  } catch {
    // Malformed JSON or read error — log and return 204 so browsers don't retry.
    console.warn("[CSP-VIOLATION] malformed report from", ip);
  }

  return new NextResponse(null, { status: 204 });
}
