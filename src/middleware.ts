import { type NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { rateLimit } from "@/lib/rate-limit";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Window constants – named instead of raw magic numbers so intent is obvious
// ---------------------------------------------------------------------------
const WINDOW_1_MIN_MS  = 60_000;   //  1 minute  – standard short window
const WINDOW_5_MIN_MS  = 300_000;  //  5 minutes – reserved for future use

// ---------------------------------------------------------------------------
// Route-specific rate limits: [pathPrefix, maxRequests, windowMs]
// Order matters: most-specific prefix must appear before any parent prefix.
// ---------------------------------------------------------------------------
const WINDOW_1_MIN_MS = 60_000; // 1 minute

const ROUTE_LIMITS: [string, number, number][] = [
  ["/api/customizations/upload", 5,  WINDOW_1_MIN_MS],
  ["/api/customizations",        10, WINDOW_1_MIN_MS],
  ["/api/sky-ads/track",         30, WINDOW_1_MIN_MS],
  ["/api/sky-ads",               30, WINDOW_1_MIN_MS],
  ["/api/raid",                  15, WINDOW_1_MIN_MS],
  ["/api/checkin",               10, WINDOW_1_MIN_MS],
  ["/api/heartbeats",            60, WINDOW_1_MIN_MS],
  ["/api/interactions/kudos",    20, WINDOW_1_MIN_MS],
  ["/api/interactions/visit",    50, WINDOW_1_MIN_MS],
  ["/api/interactions",          60, WINDOW_1_MIN_MS],
  ["/api/achievements",          30, WINDOW_1_MIN_MS],
  ["/api/loadout",               10, WINDOW_1_MIN_MS],
  ["/api/feed",                  30, WINDOW_1_MIN_MS],
  ["/api/checkout/status",       40, WINDOW_1_MIN_MS],
  ["/api/checkout",               6, WINDOW_1_MIN_MS],
  ["/api/claim",                  5, WINDOW_1_MIN_MS],
  ["/api/city",                  30, WINDOW_1_MIN_MS],
  ["/api/dev/",                  60, WINDOW_1_MIN_MS],
  ["/api/items",                 30, WINDOW_1_MIN_MS],
  ["/api/auth",                  10, WINDOW_1_MIN_MS],
];

// Lowered from 60→40 to reduce infrastructure strain from uncategorised APIs.
const DEFAULT_API:  [number, number] = [40, WINDOW_1_MIN_MS];
const DEFAULT_PAGE: [number, number] = [120, WINDOW_1_MIN_MS];

// ---------------------------------------------------------------------------
// Strict IPv4/IPv6 validation regex used inside getClientIp()
// ---------------------------------------------------------------------------
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function isValidIp(ip: string): boolean {
  return IPV4_RE.test(ip) || IPV6_RE.test(ip);
}
  // Exact-prefix match – order from most-specific to least-specific
  ["/api/customizations/upload", 5, WINDOW_1_MIN_MS],
  ["/api/customizations", 10, WINDOW_1_MIN_MS],
  ["/api/sky-ads/track", 30, WINDOW_1_MIN_MS],
  ["/api/sky-ads", 30, WINDOW_1_MIN_MS],
  ["/api/raid", 15, WINDOW_1_MIN_MS],
  ["/api/checkin", 10, WINDOW_1_MIN_MS],
  ["/api/heartbeats", 60, WINDOW_1_MIN_MS],
  ["/api/interactions/kudos", 20, WINDOW_1_MIN_MS],
  ["/api/interactions/visit", 50, WINDOW_1_MIN_MS],
  ["/api/interactions", 60, WINDOW_1_MIN_MS],
  ["/api/achievements", 30, WINDOW_1_MIN_MS],
  ["/api/loadout", 10, WINDOW_1_MIN_MS],
  ["/api/feed", 30, WINDOW_1_MIN_MS],
  ["/api/checkout/status", 40, WINDOW_1_MIN_MS],
  ["/api/checkout", 6, WINDOW_1_MIN_MS],
  ["/api/claim", 5, WINDOW_1_MIN_MS],
  ["/api/city", 30, WINDOW_1_MIN_MS],
  ["/api/dev/", 60, WINDOW_1_MIN_MS],
  ["/api/items", 30, WINDOW_1_MIN_MS],
  ["/api/auth", 10, WINDOW_1_MIN_MS],
];

const DEFAULT_API: [number, number] = [60, WINDOW_1_MIN_MS];
const DEFAULT_PAGE: [number, number] = [120, WINDOW_1_MIN_MS];

function getLimitForPath(pathname: string): {

  limit: number;
  window: number;
  group: string;
} {
  // Guard: empty / malformed pathname falls straight through to the page default.
  if (!pathname || typeof pathname !== "string") {
    return { limit: DEFAULT_PAGE[0], window: DEFAULT_PAGE[1], group: "/pages" };
  }

  // ---------------------------------------------------------------------------
  // Webhook bypass – these endpoints are called by verified third-party systems
  // (Stripe, AbacatePay, Resend) that authenticate every request with a
  // cryptographic signature checked inside each route handler.  A blanket rate
  // limit here would risk dropping legitimate payment / event webhooks under
  // burst traffic without adding any meaningful security benefit.
  // ---------------------------------------------------------------------------
  if (pathname.startsWith("/api/webhooks")) {
    return { limit: 1000, window: WINDOW_1_MIN_MS, group: "webhooks" };
  }


  for (const [prefix, limit, window] of ROUTE_LIMITS) {
    if (pathname.startsWith(prefix)) {
      return { limit, window, group: prefix };
    }
  }

  if (pathname.startsWith("/api/")) {
    return { limit: DEFAULT_API[0], window: DEFAULT_API[1], group: "/api" };
  }

  return { limit: DEFAULT_PAGE[0], window: DEFAULT_PAGE[1], group: "/pages" };
}

// ---------------------------------------------------------------------------
// Robust IP extraction with strict format validation.
// Falls back through the header chain and rejects any token that does not
// look like a real IP address, preventing header-injection attacks.
// ---------------------------------------------------------------------------
function getClientIp(request: NextRequest): string {
  const xff = request.headers.get("x-forwarded-for");
  if (xff) {
    // x-forwarded-for may contain a comma-separated chain; the leftmost is the
    // original client IP.  Validate before trusting.
    const candidate = xff.split(",")[0]?.trim() ?? "";
    if (candidate && isValidIp(candidate)) return candidate;
  }

  const xri = request.headers.get("x-real-ip")?.trim() ?? "";
  if (xri && isValidIp(xri)) return xri;

  return "unknown";
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ── 1. Rate Limit ────────────────────────────────────────────────────
  const ip    = getClientIp(request);
  const { limit, window, group } = getLimitForPath(pathname);
  const key   = `${ip}:${group}`;
  const { ok, remaining, reset } = rateLimit(key, limit, window);

  if (!ok) {
    // Attach a unique request-ID to the error body so that support teams can
    // correlate client-facing 429s with server-side logs.
    const requestId = randomUUID();
    console.warn(
      `[rate-limit] 429 ip=${ip} path=${pathname} group=${group} requestId=${requestId}`,
    );

    return new NextResponse(
      JSON.stringify({
        error:      "Too many requests. Please slow down.",
        requestId,
      }),
      {
        status: 429,
        headers: {
          "Content-Type":        "application/json",
          "Retry-After":         String(Math.ceil((reset - Date.now()) / 1000)),
          "X-RateLimit-Limit":   String(limit),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset":   String(Math.ceil(reset / 1000)),
        },
      },
    );
  }

  // ── 2. Supabase Session Refresh ──────────────────────────────────────
  // Only call Supabase when the user is actually logged in (has auth
  // cookies).  For anonymous visitors (~80%+ of viral traffic) we skip
  // the external HTTP call entirely, saving latency and Supabase quota.
  const hasSession = request.cookies
    .getAll()
    .some((c) => c.name.startsWith("sb-"));

  let supabaseResponse = NextResponse.next({ request });

  if (hasSession) {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) =>
              request.cookies.set(name, value),
            );
            supabaseResponse = NextResponse.next({ request });
            cookiesToSet.forEach(({ name, value, options }) =>
              supabaseResponse.cookies.set(name, value, options),
            );
          },
        },
      },
    );

    try {
      const { error } = await supabase.auth.getUser();
      const { data: { user }, error } = await supabase.auth.getUser();

      // If Supabase returns an auth error, handle it explicitly.
      if (error) {
        console.error(
          "Supabase authentication validation failed:",
          error.message || error,
        );
        // Proceed as anonymous: do not block request lifecycle.

        // Proceed as anonymous: do not block request lifecycle.
      } else {
        // `user` is intentionally unused here; middleware only needs to
        // validate/refresh session cookies.
      }
    } catch (error) {
      // Network failures / invalid session / infra drops can throw.
      console.error(
        "Supabase authentication validation threw an error:",
        error instanceof Error ? error.message : error,
      );

      // Proceed as anonymous: do not crash middleware.
    }
  }

  // ── 3. Security headers ──────────────────────────────────────────────
  // ── 3. Security headers
  supabaseResponse.headers.set("X-Frame-Options", "DENY");
  supabaseResponse.headers.set("X-Content-Type-Options", "nosniff");
  supabaseResponse.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  supabaseResponse.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  // ── 4. Standardised rate-limit headers (clients use these to self-throttle)
  // Header names follow the IETF draft-ietf-httpapi-ratelimit-headers spec.
  supabaseResponse.headers.set("X-RateLimit-Limit",     String(limit));
  supabaseResponse.headers.set("X-RateLimit-Remaining", String(remaining));
  supabaseResponse.headers.set("X-RateLimit-Reset",     String(Math.ceil(reset / 1000)));

  return supabaseResponse;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon\\.ico|models|fonts).*)",
  ],
};
