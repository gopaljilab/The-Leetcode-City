/**
 * In-memory sliding window rate limiter.
 *
 * State is per-process: each serverless cold-start gets its own Map.
 * Good enough for most abuse prevention. For true distributed rate
 * limiting, swap for Upstash Redis (@upstash/ratelimit).
 */

interface Entry {
  count: number;
  resetAt: number;
}

const store = new Map<string, Entry>();
let lastCleanup = Date.now();

// ── Cleanup ────────────────────────────────────────────────────────────────
// CLEANUP_INTERVAL controls how often expired entries are evicted.
// The cleanup is debounced: it runs at most once per interval and never
// blocks the hot path – it only fires when a request triggers it and the
// interval has elapsed, keeping the Map bounded without synchronous GC pressure.
const CLEANUP_INTERVAL = 60_000; // 1 minute

function cleanup() {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL) return;
  lastCleanup = now;
  // Run asynchronously so cleanup never adds latency to the caller.
  Promise.resolve().then(() => {
    for (const [key, entry] of store) {
      if (Date.now() > entry.resetAt) store.delete(key);
    }
  });
}

/**
 * Check (and consume) one request against a fixed-window counter.
 *
 * @param key     Unique identifier – usually `${ip}:${routeGroup}`
 * @param limit   Max requests allowed in `windowMs`
 * @param windowMs  Window size in milliseconds
 * @returns       `ok` = allowed, plus remaining quota & reset timestamp
 */
export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): { ok: boolean; remaining: number; reset: number } {
  cleanup();

  const now = Date.now();
  const entry = store.get(key);

  // First request in this window (or window expired)
  if (!entry || now > entry.resetAt) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, remaining: limit - 1, reset: now + windowMs };
  }

  // Window still active – check quota
  if (entry.count >= limit) {
    return { ok: false, remaining: 0, reset: entry.resetAt };
  }

  entry.count++;
  return { ok: true, remaining: limit - entry.count, reset: entry.resetAt };
}
