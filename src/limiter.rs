use dashmap::DashMap;
use itoa::Buffer as ItoaBuffer;
use ntex::http::header::{HeaderName, HeaderValue};
use ntex::service::cfg::SharedCfg;
use ntex::{http::StatusCode, Middleware, ServiceCtx};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ntex::{web, Service};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use tokio::time::interval;

#[cfg(feature = "smol")]
use smol::Timer;

const HEADER_RATELIMIT_REMAINING: &str = "x-ratelimit-remaining";
const HEADER_RATELIMIT_LIMIT: &str = "x-ratelimit-limit";
const HEADER_RATELIMIT_RESET: &str = "x-ratelimit-reset";
const HEADER_RETRY_AFTER: &str = "retry-after";

/// Token bucket algorithm implementation for rate limiting
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: usize) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, tokens: usize, now: Instant, config: &RateLimiterConfig) -> bool {
        self.refill(now, config);
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant, config: &RateLimiterConfig) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let refill_rate = config.capacity as f64 / config.window as f64;
        let new_tokens = elapsed * refill_rate;
        self.tokens = (self.tokens + new_tokens).min(config.capacity as f64);
        self.last_refill = now;
    }

    /// Whether the bucket would be back at full capacity by `now`. A full
    /// bucket behaves exactly like a missing one, so removing it loses no state.
    fn is_full(&self, now: Instant, config: &RateLimiterConfig) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let refill_rate = config.capacity as f64 / config.window as f64;
        self.tokens + elapsed * refill_rate >= config.capacity as f64
    }
}

/// Compute the epoch second at which the bucket would refill back to full capacity.
///
/// Kept allocation-free and independent of the bucket so it can run outside the
/// bucket lock (see [`RateLimiter::check_rate_limit`]).
fn compute_reset_time(tokens: f64, config: &RateLimiterConfig) -> u64 {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if tokens >= config.capacity as f64 {
        return now_secs;
    }

    let missing_tokens = config.capacity as f64 - tokens;
    let refill_rate = config.capacity as f64 / config.window as f64;
    let seconds_to_refill = missing_tokens / refill_rate;

    now_secs + seconds_to_refill.ceil() as u64
}

/// Seconds until the bucket holds at least one token again (`0` if it already does).
fn compute_retry_after(tokens: f64, config: &RateLimiterConfig) -> u64 {
    if tokens >= 1.0 {
        return 0;
    }
    let refill_rate = config.capacity as f64 / config.window as f64;
    ((1.0 - tokens) / refill_rate).ceil() as u64
}

/// Configuration for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub capacity: usize,
    pub window: u64,
    /// How often buckets that have refilled to full capacity are reclaimed.
    /// A bucket idle for `window` seconds is always full, so memory is held
    /// for at most about `window + cleanup_interval` after a key goes quiet.
    pub cleanup_interval: Duration,
    /// Whether to trust client-provided `X-Forwarded-For` / `X-Real-IP`
    /// headers. Defaults to `false`: only the direct peer socket address is
    /// used, which a client cannot spoof. Enable only behind a trusted proxy
    /// that overwrites (not appends to) these headers.
    ///
    /// Note the flip side of the secure default: when the app runs behind a
    /// reverse proxy or load balancer and this stays `false`, the peer address
    /// is the *proxy's* for every request, so all clients share one bucket and
    /// are throttled together. Set this to `true` in that deployment.
    ///
    /// Only consulted by the IP-keyed [`RateLimit`] middleware.
    pub trust_proxy_headers: bool,
    /// Soft cap on the number of per-key buckets. Once the live count reaches
    /// this value, previously unseen keys share a single overflow bucket (still
    /// rate-limited) so that an attacker cannot exhaust memory by rotating
    /// identifiers; keys that already have a bucket are unaffected.
    ///
    /// The overflow bucket is a dedicated field that always exists and is
    /// *not* counted toward this cap, so at most `max_entries + 1` buckets are
    /// live. The bound is best-effort: concurrent admissions may transiently
    /// exceed it by roughly the number of in-flight requests, but never
    /// unboundedly.
    pub max_entries: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            window: 60,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            trust_proxy_headers: false,
            max_entries: 100_000,
        }
    }
}

/// High-performance rate limiter using token bucket algorithm.
///
/// `K` is the rate-limit key; it defaults to the client [`IpAddr`] used by the
/// [`RateLimit`] middleware, but any `Hash + Eq + Clone` type works (e.g. an
/// API token id checked by hand in a handler).
pub struct RateLimiter<K = IpAddr> {
    map: DashMap<K, TokenBucket>,
    /// Shared bucket for unseen keys once `map` is full, and for requests whose
    /// key cannot be determined. Lives outside `map`, so no sentinel key is
    /// needed and it is never reclaimed by cleanup.
    overflow: Mutex<TokenBucket>,
    config: RateLimiterConfig,
    /// Live-entry count for `map`, kept as a cheap stand-in for `map.len()`
    /// (which read-locks every shard): incremented when a bucket is inserted
    /// and decremented by the number reclaimed on each [`RateLimiter::cleanup`].
    entries: AtomicUsize,
}

impl<K> RateLimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
{
    /// Create a new rate limiter with default configuration
    pub fn new(capacity: usize, window: u64) -> Arc<Self> {
        let config = RateLimiterConfig {
            capacity,
            window,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new rate limiter with custom configuration
    pub fn with_config(config: RateLimiterConfig) -> Arc<Self> {
        assert!(config.capacity > 0, "RateLimiter capacity must be greater than zero");
        assert!(config.window > 0, "RateLimiter window must be greater than zero");
        assert!(
            !config.cleanup_interval.is_zero(),
            "RateLimiter cleanup_interval must be greater than zero"
        );

        let limiter = Arc::new(RateLimiter {
            map: DashMap::new(),
            overflow: Mutex::new(TokenBucket::new(config.capacity)),
            config,
            entries: AtomicUsize::new(0),
        });

        // Start periodic cleanup if a runtime is enabled
        #[cfg(any(feature = "tokio", feature = "smol"))]
        Self::start_cleanup_task(Arc::clone(&limiter));

        limiter
    }

    #[cfg(feature = "tokio")]
    fn start_cleanup_task(limiter: Arc<Self>) {
        let cleanup_interval = limiter.config.cleanup_interval;
        let weak = Arc::downgrade(&limiter);
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            loop {
                interval.tick().await;
                // Hold the limiter via a weak reference so the task exits once
                // all strong references are gone; otherwise the task's `Arc`
                // would keep the limiter (and its DashMap) alive forever.
                let Some(limiter) = weak.upgrade() else {
                    break;
                };
                limiter.cleanup();
            }
        });
    }

    #[cfg(feature = "smol")]
    fn start_cleanup_task(limiter: Arc<Self>) {
        let cleanup_interval = limiter.config.cleanup_interval;
        let weak = Arc::downgrade(&limiter);
        smol::spawn(async move {
            loop {
                Timer::after(cleanup_interval).await;
                let Some(limiter) = weak.upgrade() else {
                    break;
                };
                limiter.cleanup();
            }
        })
        .detach();
    }

    /// Consume one token from `key`'s bucket.
    ///
    /// The key is only cloned when a new bucket is inserted; checks against an
    /// existing bucket or the overflow bucket never clone it.
    pub fn check_rate_limit(&self, key: &K) -> RateLimitResult {
        let now = Instant::now();

        // Fast path: an existing bucket. The shard guard is dropped at the end
        // of this statement, before any insert below can touch the same shard.
        let hit = self.map.get_mut(key).map(|mut bucket| {
            let allowed = bucket.consume(1, now, &self.config);
            (allowed, bucket.tokens)
        });

        let (allowed, tokens) = match hit {
            Some(hit) => hit,
            // The occupancy gate reads the `entries` atomic rather than
            // `map.len()` (which read-locks every shard), so a rotating-key
            // flood costs one lookup plus the overflow lock per request. The
            // check is best-effort: concurrent inserts may briefly exceed
            // `max_entries`, but never unboundedly.
            None if self.entries.load(Ordering::Relaxed) < self.config.max_entries => {
                let mut bucket = self.map.entry(key.clone()).or_insert_with(|| {
                    // Runs only when a bucket is actually inserted (not when a
                    // concurrent request won the race), so the counter tracks
                    // real growth.
                    self.entries.fetch_add(1, Ordering::Relaxed);
                    TokenBucket::new(self.config.capacity)
                });
                let allowed = bucket.consume(1, now, &self.config);
                (allowed, bucket.tokens)
            }
            None => self.consume_overflow(now),
        };

        self.result(allowed, tokens)
    }

    /// Consume one token from the shared overflow bucket, for requests that
    /// carry no usable key (e.g. a missing peer address).
    fn check_overflow(&self) -> RateLimitResult {
        let (allowed, tokens) = self.consume_overflow(Instant::now());
        self.result(allowed, tokens)
    }

    fn consume_overflow(&self, now: Instant) -> (bool, f64) {
        // `consume` cannot leave the bucket inconsistent, so a poisoned lock
        // is safe to reuse.
        let mut bucket = self.overflow.lock().unwrap_or_else(PoisonError::into_inner);
        let allowed = bucket.consume(1, now, &self.config);
        (allowed, bucket.tokens)
    }

    // Computed outside any bucket lock to minimize contention.
    fn result(&self, allowed: bool, tokens: f64) -> RateLimitResult {
        RateLimitResult {
            allowed,
            remaining: tokens.floor() as u32,
            reset: compute_reset_time(tokens, &self.config),
            retry_after: if allowed {
                0
            } else {
                compute_retry_after(tokens, &self.config)
            },
            limit: self.config.capacity,
        }
    }

    /// Reclaim buckets that have refilled to full capacity.
    ///
    /// Private and only ever invoked from the single task spawned by
    /// [`start_cleanup_task`], so it unconditionally reclaims full buckets on
    /// each call. Scheduling relies on that task's monotonic timer rather than
    /// wall-clock time, so NTP adjustments or a drifting system clock cannot
    /// stall cleanup.
    fn cleanup(&self) {
        let now = Instant::now();

        // Count removals inside `retain` and decrement the counter by that
        // exact amount (rather than storing `map.len()`), so `fetch_add`s from
        // inserts racing with this cleanup are preserved, not clobbered.
        let mut removed = 0usize;
        self.map.retain(|_, bucket| {
            let keep = !bucket.is_full(now, &self.config);
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            self.entries.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            active_entries: self.map.len(),
            capacity: self.config.capacity,
            window: self.config.window,
        }
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    /// Unix timestamp (seconds) at which the bucket is full again.
    pub reset: u64,
    /// Seconds until the next request would be allowed; `0` when `allowed`.
    /// Suitable for a `Retry-After` header.
    pub retry_after: u64,
    pub limit: usize,
}

/// Statistics about the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    /// Number of per-key buckets (the shared overflow bucket is not included).
    pub active_entries: usize,
    pub capacity: usize,
    pub window: u64,
}

/// Decides how [`RateLimit`] rate-limits a request.
///
/// Implemented for [`PeerIp`] (the default) and for any
/// `Fn(&WebRequest<Err>) -> Option<K>` closure, see [`RateLimit::with_key`].
pub trait KeyExtractor<K, Err> {
    /// Check `req` against `limiter`; `None` lets the request through unchecked.
    fn check_request(
        &self,
        req: &web::WebRequest<Err>,
        limiter: &RateLimiter<K>,
    ) -> Option<RateLimitResult>;
}

/// Keys requests by client IP (see [`RateLimiterConfig::trust_proxy_headers`]).
///
/// Requests without a determinable IP (no peer address, e.g. a Unix socket
/// without trusted proxy headers) share the limiter's overflow bucket.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerIp;

impl<Err> KeyExtractor<IpAddr, Err> for PeerIp {
    fn check_request(
        &self,
        req: &web::WebRequest<Err>,
        limiter: &RateLimiter<IpAddr>,
    ) -> Option<RateLimitResult> {
        Some(
            match extract_client_ip(req, limiter.config.trust_proxy_headers) {
                Some(ip) => limiter.check_rate_limit(&ip),
                None => limiter.check_overflow(),
            },
        )
    }
}

impl<K, Err, F> KeyExtractor<K, Err> for F
where
    F: Fn(&web::WebRequest<Err>) -> Option<K>,
    K: Hash + Eq + Clone + Send + Sync + 'static,
{
    fn check_request(
        &self,
        req: &web::WebRequest<Err>,
        limiter: &RateLimiter<K>,
    ) -> Option<RateLimitResult> {
        self(req).map(|key| limiter.check_rate_limit(&key))
    }
}

/// Rate limiting middleware
pub struct RateLimit<K = IpAddr, F = PeerIp> {
    pub limiter: Arc<RateLimiter<K>>,
    key: Arc<F>,
}

impl RateLimit {
    /// Rate-limit by client IP.
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        Self {
            limiter,
            key: Arc::new(PeerIp),
        }
    }
}

impl<K, F> RateLimit<K, F> {
    /// Rate-limit by a custom key derived from the request.
    ///
    /// Requests for which `key` returns `None` are passed through without
    /// rate limiting and without rate-limit headers.
    ///
    /// `key` runs before your handler, i.e. before authentication. If it keys
    /// on an unverified credential (such as a bearer token), every forged
    /// value gets its own bucket and can fill `max_entries`; validate the
    /// credential in `key`, or stack an IP-keyed [`RateLimit`] in front.
    ///
    /// ```rust,no_run
    /// use ntex::web;
    /// use ntex_ratelimiter::{RateLimit, RateLimiter};
    ///
    /// fn token_id(req: &web::WebRequest<web::DefaultError>) -> Option<String> {
    ///     // Look up and validate the bearer token, return its id.
    ///     # let _ = req; None
    /// }
    ///
    /// let limiter = RateLimiter::<String>::new(60, 60);
    /// let app = web::App::new()
    ///     .wrap(RateLimit::with_key(limiter, token_id))
    ///     .service(web::resource("/mcp").to(|| async { "ok" }));
    /// ```
    pub fn with_key<Err>(limiter: Arc<RateLimiter<K>>, key: F) -> Self
    where
        F: Fn(&web::WebRequest<Err>) -> Option<K>,
    {
        Self {
            limiter,
            key: Arc::new(key),
        }
    }
}

impl<S, K, F> Middleware<S, SharedCfg> for RateLimit<K, F> {
    type Service = RateLimitMiddlewareService<S, K, F>;

    fn create(&self, service: S, _cfg: SharedCfg) -> Self::Service {
        RateLimitMiddlewareService {
            service,
            limiter: Arc::clone(&self.limiter),
            key: Arc::clone(&self.key),
        }
    }
}

pub struct RateLimitMiddlewareService<S, K = IpAddr, F = PeerIp> {
    service: S,
    limiter: Arc<RateLimiter<K>>,
    key: Arc<F>,
}

impl<S, Err, K, F> Service<web::WebRequest<Err>> for RateLimitMiddlewareService<S, K, F>
where
    S: Service<web::WebRequest<Err>, Response = web::WebResponse, Error = web::Error> + 'static,
    Err: web::ErrorRenderer,
    F: KeyExtractor<K, Err>,
{
    type Response = web::WebResponse;
    type Error = web::Error;

    async fn call(
        &self,
        req: web::WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let Some(result) = self.key.check_request(&req, &self.limiter) else {
            return ctx.call(&self.service, req).await;
        };

        if !result.allowed {
            return Err(RateLimitError(result).into());
        }

        let mut response = ctx.call(&self.service, req).await?;

        // Add rate limit headers to successful responses
        add_rate_limit_headers(response.headers_mut(), &result);

        Ok(response)
    }
}

/// Extract client IP from request, considering proxy headers when trusted.
///
/// When `trust_proxy_headers` is `false` (the default), proxy headers are
/// ignored entirely and the peer socket address is used, since clients can
/// forge `X-Forwarded-For` / `X-Real-IP` to bypass rate limiting.
///
/// Returns `None` when no IP can be determined. Callers must not substitute a
/// fixed address (e.g. `127.0.0.1`), which would merge these requests with
/// genuine requests from that address.
fn extract_client_ip<Err>(req: &web::WebRequest<Err>, trust_proxy_headers: bool) -> Option<IpAddr> {
    if trust_proxy_headers {
        // Check X-Forwarded-For header first
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(ip) = forwarded_str.split(',').next() {
                    let ip = ip.trim();
                    if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                        // `0.0.0.0` / `::` is never a valid client source.
                        if !parsed_ip.is_unspecified() {
                            return Some(parsed_ip);
                        }
                    }
                }
            }
        }

        // Check X-Real-IP header
        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                let ip = ip_str.trim();
                if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                    if !parsed_ip.is_unspecified() {
                        return Some(parsed_ip);
                    }
                }
            }
        }
    }

    // Fallback to the actual peer socket address. This is allocation-free
    // (no string round-trip through `connection_info()`) and cannot be
    // spoofed by the client.
    req.peer_addr().map(|peer| peer.ip())
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut ntex::http::HeaderMap, result: &RateLimitResult) {
    // `itoa` formats the integers on the stack (no heap allocation), and
    // `HeaderValue::from_str` copies the bytes into an owned value, so a single
    // buffer can be reused for all three headers.
    let mut buf = ItoaBuffer::new();
    if let Ok(value) = HeaderValue::from_str(buf.format(result.remaining)) {
        headers.insert(HeaderName::from_static(HEADER_RATELIMIT_REMAINING), value);
    }
    if let Ok(value) = HeaderValue::from_str(buf.format(result.limit)) {
        headers.insert(HeaderName::from_static(HEADER_RATELIMIT_LIMIT), value);
    }
    if let Ok(value) = HeaderValue::from_str(buf.format(result.reset)) {
        headers.insert(HeaderName::from_static(HEADER_RATELIMIT_RESET), value);
    }
}

/// Error returned by the middleware when a request is rate-limited.
#[derive(Debug)]
struct RateLimitError(RateLimitResult);

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded. Remaining: {}, Reset: {}, Limit: {}",
            self.0.remaining, self.0.reset, self.0.limit
        )
    }
}

impl web::error::WebResponseError for RateLimitError {
    fn error_response(&self, _: &ntex::web::HttpRequest) -> web::HttpResponse {
        let r = &self.0;
        // Only integers are interpolated, so no JSON escaping is needed.
        let body = format!(
            r#"{{"code":429,"message":"Rate limit exceeded","data":{{"remaining":{},"reset":{},"limit":{}}}}}"#,
            r.remaining, r.reset, r.limit
        );

        let mut buf = ItoaBuffer::new();
        web::HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
            .set_header("content-type", "application/json")
            .set_header(HEADER_RATELIMIT_REMAINING, buf.format(r.remaining))
            .set_header(HEADER_RATELIMIT_LIMIT, buf.format(r.limit))
            .set_header(HEADER_RATELIMIT_RESET, buf.format(r.reset))
            .set_header(HEADER_RETRY_AFTER, buf.format(r.retry_after))
            .body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntex::web::test::TestRequest;

    #[test]
    fn test_token_bucket_basic() {
        let config = RateLimiterConfig {
            capacity: 5,
            window: 10,
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(5);
        let now = Instant::now();

        // Should allow up to capacity
        for _ in 0..5 {
            assert!(bucket.consume(1, now, &config));
        }

        // Should deny when capacity exceeded
        assert!(!bucket.consume(1, now, &config));
        assert_eq!(bucket.tokens.floor() as u32, 0);
    }

    #[test]
    fn test_token_bucket_refill() {
        let config = RateLimiterConfig {
            capacity: 10,
            window: 10, // 1 token per second
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(10);
        let now = Instant::now();

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.consume(1, now, &config));
        }
        assert!(!bucket.consume(1, now, &config));

        // After 5 seconds, should have 5 tokens
        let later = now + Duration::from_secs(5);
        bucket.refill(later, &config);
        assert_eq!(bucket.tokens.floor() as u32, 5);

        // Should be able to consume 5 tokens
        for _ in 0..5 {
            assert!(bucket.consume(1, later, &config));
        }
        assert!(!bucket.consume(1, later, &config));
    }

    // The rate-limit checks themselves are synchronous, so the assertion logic
    // is runtime-independent. Only `RateLimiter` construction needs a runtime,
    // because it spawns the cleanup task; `with_rt` provides that context for
    // whichever runtime feature is enabled.
    fn with_rt(f: impl FnOnce()) {
        #[cfg(feature = "tokio")]
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { f() });

        #[cfg(feature = "smol")]
        smol::block_on(async { f() });
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn config(capacity: usize, max_entries: usize) -> RateLimiterConfig {
        RateLimiterConfig {
            capacity,
            window: 60,
            max_entries,
            ..Default::default()
        }
    }

    #[test]
    fn test_rate_limiter() {
        with_rt(|| {
            let limiter = RateLimiter::with_config(RateLimiterConfig {
                capacity: 5,
                window: 1,
                ..Default::default()
            });
            let ip = ip("192.168.1.1");

            // Should allow up to capacity
            for i in 0..5 {
                let result = limiter.check_rate_limit(&ip);
                assert!(result.allowed, "Request {} should be allowed", i + 1);
                assert_eq!(result.remaining, 4 - i as u32);
                assert_eq!(result.retry_after, 0);
            }

            // Should deny when capacity exceeded
            let result = limiter.check_rate_limit(&ip);
            assert!(!result.allowed);
            assert_eq!(result.remaining, 0);
            assert_eq!(result.retry_after, 1);
        });
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        with_rt(|| {
            // Different IPs should have separate limits
            let limiter = RateLimiter::new(2, 60);
            let result1 = limiter.check_rate_limit(&ip("192.168.1.1"));
            let result2 = limiter.check_rate_limit(&ip("192.168.1.2"));

            assert!(result1.allowed);
            assert!(result2.allowed);
            assert_eq!(result1.remaining, 1);
            assert_eq!(result2.remaining, 1);
        });
    }

    #[test]
    fn test_string_keys_independent() {
        with_rt(|| {
            let limiter = RateLimiter::<String>::new(2, 60);
            let a = "token-a".to_string();
            let b = "token-b".to_string();

            assert!(limiter.check_rate_limit(&a).allowed);
            assert!(limiter.check_rate_limit(&a).allowed);
            assert!(!limiter.check_rate_limit(&a).allowed);

            let result = limiter.check_rate_limit(&b);
            assert!(result.allowed, "token-b must not share token-a's bucket");
            assert_eq!(result.remaining, 1);
            assert_eq!(limiter.stats().active_entries, 2);
        });
    }

    #[test]
    fn test_overflow_bucket() {
        with_rt(|| {
            let limiter = RateLimiter::with_config(config(1, 2));
            let (ip1, ip2) = (ip("10.0.0.1"), ip("10.0.0.2"));

            // ip1 and ip2 each get their own bucket (capacity 1).
            assert!(limiter.check_rate_limit(&ip1).allowed);
            assert!(limiter.check_rate_limit(&ip2).allowed);

            // Map is at capacity; unseen ip3 is routed to the overflow bucket,
            // which is fresh (capacity 1) -> allowed.
            assert!(
                limiter.check_rate_limit(&ip("10.0.0.3")).allowed,
                "first overflow hit should be allowed"
            );
            // ip4 is unseen but shares the now-empty overflow bucket -> denied.
            assert!(
                !limiter.check_rate_limit(&ip("10.0.0.4")).allowed,
                "second overflow hit should be denied"
            );

            // The overflow bucket is not part of the map.
            assert_eq!(limiter.map.len(), 2);
            assert_eq!(limiter.entries.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn test_overflow_leaves_existing_keys_alone() {
        with_rt(|| {
            let limiter = RateLimiter::<String>::with_config(config(2, 1));
            let known = "known".to_string();

            assert!(limiter.check_rate_limit(&known).allowed);

            // Exhaust the overflow bucket with unseen keys.
            assert!(limiter.check_rate_limit(&"new-1".to_string()).allowed);
            assert!(limiter.check_rate_limit(&"new-2".to_string()).allowed);
            assert!(!limiter.check_rate_limit(&"new-3".to_string()).allowed);

            // The tracked key keeps its own bucket.
            let result = limiter.check_rate_limit(&known);
            assert!(result.allowed);
            assert_eq!(result.remaining, 0);
            assert_eq!(limiter.stats().active_entries, 1);
        });
    }

    /// Key whose `Clone` impl counts invocations; identity is `id` only.
    struct CountingKey {
        id: u32,
        clones: Arc<AtomicUsize>,
    }

    impl Clone for CountingKey {
        fn clone(&self) -> Self {
            self.clones.fetch_add(1, Ordering::Relaxed);
            Self {
                id: self.id,
                clones: Arc::clone(&self.clones),
            }
        }
    }

    impl PartialEq for CountingKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for CountingKey {}

    impl Hash for CountingKey {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    #[test]
    fn test_check_clones_only_on_insert() {
        with_rt(|| {
            let clones = Arc::new(AtomicUsize::new(0));
            let key = |id| CountingKey {
                id,
                clones: Arc::clone(&clones),
            };
            let limiter = RateLimiter::with_config(config(10, 1));
            let (a, b) = (key(1), key(2));

            limiter.check_rate_limit(&a);
            assert_eq!(clones.load(Ordering::Relaxed), 1, "insert clones once");

            for _ in 0..5 {
                limiter.check_rate_limit(&a);
            }
            assert_eq!(clones.load(Ordering::Relaxed), 1, "existing bucket: no clone");

            // Map is full, so `b` goes to the overflow bucket without a clone.
            limiter.check_rate_limit(&b);
            assert_eq!(clones.load(Ordering::Relaxed), 1, "overflow: no clone");
        });
    }

    #[test]
    fn test_concurrent_entries_do_not_drift() {
        with_rt(|| {
            const THREADS: u32 = 8;
            const KEYS: u32 = 500;
            // 1000 tokens/s, so drained buckets refill within milliseconds.
            let limiter = RateLimiter::<u32>::with_config(RateLimiterConfig {
                window: 1,
                ..config(1_000, 1_000_000)
            });

            std::thread::scope(|s| {
                for t in 0..THREADS {
                    let limiter = &limiter;
                    s.spawn(move || {
                        // Overlapping key ranges force racing inserts of the
                        // same key across threads.
                        for k in 0..KEYS {
                            limiter.check_rate_limit(&((k + t * 7) % KEYS));
                        }
                    });
                }
            });

            assert_eq!(limiter.map.len(), KEYS as usize);
            assert_eq!(limiter.entries.load(Ordering::Relaxed), KEYS as usize);

            // Once every bucket has refilled, cleanup reclaims all of them and
            // the counter must return to zero.
            std::thread::sleep(Duration::from_millis(50));
            limiter.cleanup();
            assert_eq!(limiter.map.len(), 0);
            assert_eq!(limiter.entries.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn test_cleanup_reclaims_only_full_buckets() {
        with_rt(|| {
            // 1 token per 6s: a drained bucket stays non-full for the test.
            let limiter = RateLimiter::<&str>::with_config(config(10, 100));
            limiter.check_rate_limit(&"busy");
            limiter.cleanup();
            assert_eq!(limiter.stats().active_entries, 1, "non-full bucket kept");

            // 1000 tokens/s: refills within a millisecond.
            let limiter = RateLimiter::<&str>::with_config(RateLimiterConfig {
                window: 1,
                ..config(1_000, 100)
            });
            limiter.check_rate_limit(&"idle");
            std::thread::sleep(Duration::from_millis(20));
            limiter.cleanup();
            assert_eq!(limiter.stats().active_entries, 0, "full bucket reclaimed");
            assert_eq!(limiter.map.len(), 0);
        });
    }

    #[test]
    fn test_unknown_peer_uses_overflow_bucket() {
        with_rt(|| {
            let limiter = RateLimiter::with_config(config(1, 100));
            let localhost = ip("127.0.0.1");

            // Test requests carry no peer address.
            let req = TestRequest::default().to_srv_request();
            let result = PeerIp.check_request(&req, &limiter).unwrap();
            assert!(result.allowed);
            assert!(
                !PeerIp.check_request(&req, &limiter).unwrap().allowed,
                "unknown peers share the overflow bucket"
            );

            // No per-IP bucket was created, so genuine localhost is unaffected.
            assert_eq!(limiter.stats().active_entries, 0);
            assert!(limiter.check_rate_limit(&localhost).allowed);
            assert_eq!(limiter.stats().active_entries, 1);
        });
    }

    #[test]
    fn test_custom_key_extractor() {
        with_rt(|| {
            let limiter = RateLimiter::<String>::new(1, 60);
            let key = |req: &web::WebRequest<web::DefaultError>| {
                req.headers()
                    .get("x-api-token")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let mw = RateLimit::with_key(Arc::clone(&limiter), key);

            let with_token = || {
                TestRequest::default()
                    .header("x-api-token", "t1")
                    .to_srv_request()
            };
            assert!(mw.key.check_request(&with_token(), &limiter).unwrap().allowed);
            assert!(!mw.key.check_request(&with_token(), &limiter).unwrap().allowed);

            // No key -> not rate-limited.
            let req = TestRequest::default().to_srv_request();
            assert!(mw.key.check_request(&req, &limiter).is_none());
        });
    }

    #[test]
    fn test_error_response() {
        use ntex::web::error::WebResponseError;

        let err = RateLimitError(RateLimitResult {
            allowed: false,
            remaining: 0,
            reset: 1_700_000_000,
            retry_after: 3,
            limit: 100,
        });
        let res = err.error_response(&TestRequest::default().to_http_request());
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        let header = |name| res.headers().get(name).unwrap().to_str().unwrap();
        assert_eq!(header(HEADER_RETRY_AFTER), "3");
        assert_eq!(header(HEADER_RATELIMIT_REMAINING), "0");
        assert_eq!(header(HEADER_RATELIMIT_LIMIT), "100");
        assert_eq!(header(HEADER_RATELIMIT_RESET), "1700000000");
        assert_eq!(header("content-type"), "application/json");

        let body = match res.body() {
            ntex::http::body::ResponseBody::Body(ntex::http::body::Body::Bytes(b)) => b.clone(),
            other => panic!("unexpected body: {other:?}"),
        };
        assert_eq!(
            &body[..],
            br#"{"code":429,"message":"Rate limit exceeded","data":{"remaining":0,"reset":1700000000,"limit":100}}"#
        );
    }

    #[test]
    #[should_panic(expected = "cleanup_interval must be greater than zero")]
    fn test_zero_cleanup_interval_rejected() {
        // The assertion fires before the cleanup task is spawned, so no runtime
        // is needed and both the tokio and smol paths are covered.
        let _ = RateLimiter::<IpAddr>::with_config(RateLimiterConfig {
            cleanup_interval: Duration::ZERO,
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_zero_capacity_rejected() {
        let _ = RateLimiter::<IpAddr>::new(0, 60);
    }

    #[test]
    fn test_extract_client_ip_trust_proxy() {
        // Trusted: X-Forwarded-For is honored.
        let req = TestRequest::default()
            .header("x-forwarded-for", "1.2.3.4")
            .to_srv_request();
        assert_eq!(extract_client_ip(&req, true), Some(ip("1.2.3.4")));

        // Untrusted (default): XFF is ignored; test requests have no peer
        // address, so no IP can be determined.
        let req = TestRequest::default()
            .header("x-forwarded-for", "1.2.3.4")
            .to_srv_request();
        assert_eq!(extract_client_ip(&req, false), None);

        // Trusted: X-Real-IP is honored.
        let req = TestRequest::default()
            .header("x-real-ip", "5.6.7.8")
            .to_srv_request();
        assert_eq!(extract_client_ip(&req, true), Some(ip("5.6.7.8")));

        // Trusted but malformed header -> falls back to peer (none here).
        let req = TestRequest::default()
            .header("x-forwarded-for", "not-an-ip")
            .to_srv_request();
        assert_eq!(extract_client_ip(&req, true), None);

        // Trusted but unspecified (`0.0.0.0`) header -> rejected.
        let req = TestRequest::default()
            .header("x-forwarded-for", "0.0.0.0")
            .to_srv_request();
        assert_eq!(extract_client_ip(&req, true), None);

        // `TestRequest::peer_addr` does not reach `WebRequest::peer_addr` in
        // ntex 3, so the peer-address path cannot be exercised here.
    }
}
