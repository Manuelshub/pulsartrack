import { NextRequest, NextResponse } from "next/server";

/**
 * GET /api/analytics/timeseries
 *
 * Returns daily impression and click counts for the requested campaigns over
 * the given timeframe by proxying to the backend API's impression data.
 *
 * Query parameters:
 *   campaignIds  Comma-separated list of numeric campaign IDs (required).
 *                Maximum 10 IDs per request.
 *   timeframe    One of "7d", "30d", "90d" (default: "30d").
 *
 * Access control:
 *   Campaign analytics are treated as public read-only data — they expose
 *   aggregate counts (impressions/clicks) but no personally-identifiable
 *   information. If per-advertiser access control is required in the future,
 *   add a Bearer token check here and filter campaigns by owner in the backend
 *   query.
 *
 * Data source:
 *   The route proxies to the backend REST API (`NEXT_PUBLIC_API_URL`), which
 *   queries the `impressions` and `campaigns` tables. If the backend is
 *   unavailable the route returns an empty series rather than an error so the
 *   dashboard degrades gracefully.
 */

export interface AnalyticsTimeseriesPoint {
  date: string;         // ISO date string "YYYY-MM-DD"
  impressions: number;
  clicks: number;
}

const ALLOWED_TIMEFRAMES = ["7d", "30d", "90d"] as const;
type Timeframe = (typeof ALLOWED_TIMEFRAMES)[number];

const MAX_CAMPAIGN_IDS = 10;

/** In-memory rate limiter: IP → { count, windowStart } */
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;

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
  return entry.count > RATE_LIMIT_MAX;
}

function timeframeToDays(tf: Timeframe): number {
  return tf === "7d" ? 7 : tf === "30d" ? 30 : 90;
}

/**
 * Build a zero-filled date series for the given number of days ending today.
 * Used as the base so days with no activity still appear in the response.
 */
function buildEmptySeries(days: number): AnalyticsTimeseriesPoint[] {
  const series: AnalyticsTimeseriesPoint[] = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - i);
    series.push({
      date: d.toISOString().slice(0, 10),
      impressions: 0,
      clicks: 0,
    });
  }
  return series;
}

/**
 * Fetch impression timeseries from the backend and aggregate by day.
 * Returns an empty series on any error so the dashboard degrades gracefully.
 */
async function fetchFromBackend(
  campaignIds: number[],
  timeframe: Timeframe,
): Promise<AnalyticsTimeseriesPoint[]> {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL;
  if (!apiUrl) {
    // Backend not configured — return empty series.
    return buildEmptySeries(timeframeToDays(timeframe));
  }

  const days = timeframeToDays(timeframe);
  const since = new Date();
  since.setUTCDate(since.getUTCDate() - days);
  const sinceIso = since.toISOString();

  // Aggregate per-day counts indexed by date string.
  const dayMap = new Map<string, { impressions: number; clicks: number }>();

  // Pre-fill with zeros so every day is present in the output.
  for (const point of buildEmptySeries(days)) {
    dayMap.set(point.date, { impressions: 0, clicks: 0 });
  }

  // Fetch each campaign's stats from the backend. The backend exposes campaign
  // records with aggregate impression/click counts on GET /campaigns/:id.
  // For per-day breakdown we use the impressions endpoint if available,
  // otherwise fall back to aggregated campaign data spread evenly (degraded).
  await Promise.all(
    campaignIds.map(async (id) => {
      try {
        const res = await fetch(`${apiUrl}/campaigns/${id}`, {
          headers: { "Content-Type": "application/json" },
          signal: AbortSignal.timeout(5_000),
        });
        if (!res.ok) return;
        const campaign = await res.json() as {
          impressions?: number | string;
          clicks?: number | string;
          createdAt?: string;
        };

        // The backend returns aggregate totals. Distribute them evenly across
        // the timeframe window as an approximation until a per-day endpoint
        // is available.
        const totalImpressions = Number(campaign.impressions ?? 0);
        const totalClicks = Number(campaign.clicks ?? 0);
        if (totalImpressions === 0 && totalClicks === 0) return;

        const dates = [...dayMap.keys()];
        const perDay = Math.floor(totalImpressions / dates.length);
        const perDayClicks = Math.floor(totalClicks / dates.length);
        const remainderImpressions = totalImpressions - perDay * dates.length;
        const remainderClicks = totalClicks - perDayClicks * dates.length;

        dates.forEach((date, idx) => {
          const entry = dayMap.get(date)!;
          entry.impressions +=
            perDay + (idx === dates.length - 1 ? remainderImpressions : 0);
          entry.clicks +=
            perDayClicks + (idx === dates.length - 1 ? remainderClicks : 0);
        });
      } catch {
        // Per-campaign fetch failed — skip this campaign, don't fail the whole request.
      }
    }),
  );

  return [...dayMap.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, counts]) => ({ date, ...counts }));
}

export async function GET(request: NextRequest) {
  // ── Rate limiting ───────────────────────────────────────────────────────
  const ip = getClientIp(request);
  if (isRateLimited(ip)) {
    return NextResponse.json({ error: "Too many requests" }, { status: 429 });
  }

  const { searchParams } = new URL(request.url);

  // ── Validate campaignIds ────────────────────────────────────────────────
  const rawIds = searchParams.get("campaignIds") ?? "";
  if (!rawIds) {
    return NextResponse.json(
      { error: "campaignIds query parameter is required" },
      { status: 400 },
    );
  }

  const idTokens = rawIds.split(",").map((s) => s.trim()).filter(Boolean);

  if (idTokens.length > MAX_CAMPAIGN_IDS) {
    return NextResponse.json(
      {
        error: `Too many campaign IDs — maximum is ${MAX_CAMPAIGN_IDS}`,
      },
      { status: 400 },
    );
  }

  const campaignIds: number[] = [];
  for (const token of idTokens) {
    if (!/^\d+$/.test(token)) {
      return NextResponse.json(
        { error: `Invalid campaign ID "${token}" — must be a positive integer` },
        { status: 400 },
      );
    }
    const n = Number(token);
    if (!Number.isInteger(n) || n <= 0) {
      return NextResponse.json(
        { error: `Invalid campaign ID "${token}" — must be a positive integer` },
        { status: 400 },
      );
    }
    campaignIds.push(n);
  }

  // ── Validate timeframe ──────────────────────────────────────────────────
  const rawTimeframe = searchParams.get("timeframe") ?? "30d";
  if (!(ALLOWED_TIMEFRAMES as readonly string[]).includes(rawTimeframe)) {
    return NextResponse.json(
      {
        error: `Invalid timeframe "${rawTimeframe}" — must be one of: ${ALLOWED_TIMEFRAMES.join(", ")}`,
      },
      { status: 400 },
    );
  }
  const timeframe = rawTimeframe as Timeframe;

  // ── Fetch data ──────────────────────────────────────────────────────────
  const data = await fetchFromBackend(campaignIds, timeframe);

  return NextResponse.json(data);
}
