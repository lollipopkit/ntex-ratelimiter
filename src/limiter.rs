use dashmap::DashMap;
use itoa::Buffer as ItoaBuffer;
use ntex::http::header::{HeaderName, HeaderValue};
use ntex::service::cfg::SharedCfg;
use ntex::{http::StatusCode, Middleware, ServiceCtx};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ntex::{web, Service};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use tokio::time::interval;

#[cfg(feature = "smol")]
use smol::Timer;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

const HEADER_RATELIMIT_REMAINING: &str = "x-ratelimit-remaining";
const HEADER_RATELIMIT_LIMIT: &str = "x-ratelimit-limit";
const HEADER_RATELIMIT_RESET: &str = "x-ratelimit-reset";

/// Sentinel IP used as a shared bucket for previously-unseen clients once the
/// map reaches [`RateLimiterConfig::max_entries`], so that attackers rotating
/// source identifiers cannot exhaust memory and remain rate-limited.
/// The unspecified address (`0.0.0.0`) is never a valid client source, and
/// [`extract_client_ip`] rejects unspecified values parsed from proxy headers,
/// so this sentinel never collides with an accepted client IP.
const OVERFLOW_KEY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

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

    /// Check if this bucket is stale (hasn't been used recently)
    fn is_stale(&self, now: Instant, stale_threshold: Duration) -> bool {
        now.duration_since(self.last_refill) > stale_threshold
    }
}

/// Compute the epoch second at which the bucket would refill back to full capacity.
///
/// Kept allocation-free and independent of the bucket so it can run outside the
/// `DashMap` shard lock (see [`RateLimiter::check_rate_limit`]).
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

/// Configuration for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub capacity: usize,
    pub window: u64,
    pub cleanup_interval: Duration,
    pub stale_threshold: Duration,
    /// Whether to trust client-provided `X-Forwarded-For` / `X-Real-IP`
    /// headers. Defaults to `false`: only the direct peer socket address is
    /// used, which a client cannot spoof. Enable only behind a trusted proxy
    /// that overwrites (not appends to) these headers.
    ///
    /// Note the flip side of the secure default: when the app runs behind a
    /// reverse proxy or load balancer and this stays `false`, the peer address
    /// is the *proxy's* for every request, so all clients share one bucket and
    /// are throttled together. Set this to `true` in that deployment.
    pub trust_proxy_headers: bool,
    /// Soft cap on the number of tracked client buckets. Once the live count
    /// reaches this value, previously unseen clients share a single overflow
    /// bucket (still rate-limited) so that an attacker cannot exhaust memory by
    /// rotating source identifiers. The shared overflow bucket is not
    /// additional — it counts toward this cap (occupying one of the
    /// `max_entries` slots). The bound is best-effort: concurrent admissions
    /// may transiently exceed it by roughly the number of in-flight requests,
    /// but never unboundedly.
    pub max_entries: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            window: 60,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            stale_threshold: Duration::from_secs(3600), // 1 hour
            trust_proxy_headers: false,
            max_entries: 100_000,
        }
    }
}

/// High-performance rate limiter using token bucket algorithm
pub struct RateLimiter {
    map: DashMap<IpAddr, TokenBucket>,
    config: RateLimiterConfig,
    /// Live-entry count for `map`, kept as a cheap stand-in for `map.len()`
    /// (which read-locks every shard): incremented when a bucket is inserted
    /// and decremented by the number reclaimed on each [`RateLimiter::cleanup`].
    entries: AtomicUsize,
}

impl RateLimiter {
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
        assert!(config.window > 0, "RateLimiter window must be greater than zero");
        assert!(
            !config.cleanup_interval.is_zero(),
            "RateLimiter cleanup_interval must be greater than zero"
        );

        let limiter = Arc::new(RateLimiter {
            map: DashMap::new(),
            config,
            entries: AtomicUsize::new(0),
        });

        // Start periodic cleanup if a runtime is enabled
        #[cfg(any(feature = "tokio", feature = "smol"))]
        Self::start_cleanup_task(Arc::clone(&limiter));

        limiter
    }

    #[cfg(feature = "tokio")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
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
                limiter.cleanup().await;
            }
        });
    }

    #[cfg(feature = "smol")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
        let cleanup_interval = limiter.config.cleanup_interval;
        let weak = Arc::downgrade(&limiter);
        smol::spawn(async move {
            loop {
                Timer::after(cleanup_interval).await;
                let Some(limiter) = weak.upgrade() else {
                    break;
                };
                limiter.cleanup().await;
            }
        })
        .detach();
    }

    /// Check rate limit for a given identifier (usually IP address)
    pub fn check_rate_limit(&self, identifier: IpAddr) -> RateLimitResult {
        let now = Instant::now();
        let limit = self.config.capacity;

        // When the map is at capacity and this client is not already tracked,
        // route it to a shared overflow bucket. This keeps memory bounded under
        // a rotating-IP attack while still rate-limiting the attacker (alongside
        // any other unseen clients). The check is best-effort: concurrent
        // inserts may briefly exceed `max_entries`, but never unboundedly.
        //
        // The occupancy gate reads the `entries` atomic rather than `map.len()`
        // (which read-locks every shard), so the common under-capacity path
        // takes no extra lookups. Only once the map is full do we pay a single
        // `contains_key` to tell an already-tracked client apart from a new one
        // — exactly the path a rotating-IP flood takes, where a full `len()`
        // scan per request would amplify the very DoS this cap defends against.
        let key = if self.entries.load(Ordering::Relaxed) < self.config.max_entries
            || self.map.contains_key(&identifier)
        {
            identifier
        } else {
            OVERFLOW_KEY
        };

        // Hold the shard's write guard only for the bucket mutation; the reset
        // timestamp is computed afterwards (allocation-free) to minimize
        // contention on the per-shard lock.
        let (allowed, tokens) = {
            let mut bucket = self.map.entry(key).or_insert_with(|| {
                // Runs only when a new bucket is actually inserted, so the
                // counter tracks real growth (including the overflow bucket,
                // matching the previous `len()`-based accounting).
                self.entries.fetch_add(1, Ordering::Relaxed);
                TokenBucket::new(limit)
            });
            let allowed = bucket.consume(1, now, &self.config);
            (allowed, bucket.tokens)
        };

        RateLimitResult {
            allowed,
            remaining: tokens.floor() as u32,
            reset: compute_reset_time(tokens, &self.config),
            limit,
        }
    }

    /// Clean up stale entries.
    ///
    /// Private and only ever invoked from the single task spawned by
    /// [`start_cleanup_task`], so it unconditionally reclaims stale buckets on
    /// each call. Scheduling relies on that task's monotonic timer rather than
    /// wall-clock time, so NTP adjustments or a drifting system clock cannot
    /// stall cleanup.
    async fn cleanup(&self) {
        let now = Instant::now();
        let stale_threshold = self.config.stale_threshold;

        // Count removals inside `retain` and decrement the counter by that
        // exact amount (rather than storing `map.len()`), so `fetch_add`s from
        // inserts racing with this cleanup are preserved, not clobbered.
        let mut removed = 0usize;
        self.map.retain(|_, bucket| {
            let keep = !bucket.is_stale(now, stale_threshold);
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            self.entries.fetch_sub(removed, Ordering::Relaxed);

            if cfg!(debug_assertions) {
                eprintln!("Cleaned {removed} stale rate limit entries");
            }
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
    pub reset: u64,
    pub limit: usize,
}

/// Statistics about the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub active_entries: usize,
    pub capacity: usize,
    pub window: u64,
}

/// Rate limiting middleware
pub struct RateLimit {
    pub limiter: Arc<RateLimiter>,
}

impl RateLimit {
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }
}

impl<S> Middleware<S, SharedCfg> for RateLimit {
    type Service = RateLimitMiddlewareService<S>;

    fn create(&self, service: S, _cfg: SharedCfg) -> Self::Service {
        RateLimitMiddlewareService {
            service,
            limiter: Arc::clone(&self.limiter),
        }
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    limiter: Arc<RateLimiter>,
}

impl<S, Err> Service<web::WebRequest<Err>> for RateLimitMiddlewareService<S>
where
    S: Service<web::WebRequest<Err>, Response = web::WebResponse, Error = web::Error> + 'static,
    Err: web::ErrorRenderer,
{
    type Response = web::WebResponse;
    type Error = web::Error;

    async fn call(
        &self,
        req: web::WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let ip = extract_client_ip(&req, self.limiter.config.trust_proxy_headers);

        let result = self.limiter.check_rate_limit(ip);

        if !result.allowed {
            return Err(RateLimitError::from(result).into());
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
fn extract_client_ip<Err>(req: &web::WebRequest<Err>, trust_proxy_headers: bool) -> IpAddr {
    if trust_proxy_headers {
        // Check X-Forwarded-For header first
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(ip) = forwarded_str.split(',').next() {
                    let ip = ip.trim();
                    if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                        // Reject `0.0.0.0` / `::` so a forged header cannot map
                        // a client onto the `OVERFLOW_KEY` sentinel.
                        if !parsed_ip.is_unspecified() {
                            return parsed_ip;
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
                        return parsed_ip;
                    }
                }
            }
        }
    }

    // Fallback to the actual peer socket address. This is allocation-free
    // (no string round-trip through `connection_info()`) and cannot be
    // spoofed by the client.
    if let Some(peer) = req.peer_addr() {
        return peer.ip();
    }

    // Default to localhost if all else fails
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
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

/// Rate limit error response
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
struct RateLimitErrorData {
    remaining: u32,
    reset: u64,
    limit: usize,
}

/// Wrapper struct used only when serializing the JSON error body.
#[cfg(feature = "json")]
#[derive(Debug, Serialize, Deserialize)]
struct RateLimitErrorResponse {
    code: u32,
    message: String,
    data: RateLimitErrorData,
}

#[derive(Debug)]
struct RateLimitError {
    data: RateLimitErrorData,
}

impl From<RateLimitResult> for RateLimitError {
    fn from(result: RateLimitResult) -> Self {
        Self {
            data: RateLimitErrorData {
                remaining: result.remaining,
                reset: result.reset,
                limit: result.limit,
            },
        }
    }
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded. Remaining: {}, Reset: {}, Limit: {}",
            self.data.remaining, self.data.reset, self.data.limit
        )
    }
}

impl web::error::WebResponseError for RateLimitError {
    fn error_response(&self, _: &ntex::web::HttpRequest) -> web::HttpResponse {
        #[cfg(feature = "json")]
        let body = {
            let error_response = RateLimitErrorResponse {
                code: 429,
                message: "Rate limit exceeded".to_string(),
                data: RateLimitErrorData {
                    remaining: self.data.remaining,
                    reset: self.data.reset,
                    limit: self.data.limit,
                },
            };
            serde_json::to_string(&error_response)
                .unwrap_or_else(|_| r#"{"code":429,"message":"Rate limit exceeded"}"#.to_string())
        };

        #[cfg(not(feature = "json"))]
        let body = format!(
            r#"{{"code":429,"message":"Rate limit exceeded","data":{{"remaining":{},"reset":{},"limit":{}}}}}"#,
            self.data.remaining, self.data.reset, self.data.limit
        );

        let mut buf = ItoaBuffer::new();
        web::HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
            .set_header("content-type", "application/json")
            .set_header(HEADER_RATELIMIT_REMAINING, buf.format(self.data.remaining))
            .set_header(HEADER_RATELIMIT_LIMIT, buf.format(self.data.limit))
            .set_header(HEADER_RATELIMIT_RESET, buf.format(self.data.reset))
            .body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // The rate-limit checks themselves are synchronous (`check_rate_limit` does
    // not await), so the assertion logic is shared between runtimes. Only the
    // `RateLimiter` construction needs a runtime, because it spawns the cleanup
    // task. Each runtime therefore gets a thin wrapper that drives a runtime
    // context around the shared checks.

    fn check_capacity_5(limiter: &RateLimiter) {
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

        // Should allow up to capacity
        for i in 0..5 {
            let result = limiter.check_rate_limit(ip);
            assert!(result.allowed, "Request {} should be allowed", i + 1);
            assert_eq!(result.remaining, 4 - i as u32);
        }

        // Should deny when capacity exceeded
        let result = limiter.check_rate_limit(ip);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    fn check_different_ips(limiter: &RateLimiter) {
        // Different IPs should have separate limits
        let ip1 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let ip2 = "192.168.1.2".parse::<IpAddr>().unwrap();
        let result1 = limiter.check_rate_limit(ip1);
        let result2 = limiter.check_rate_limit(ip2);

        assert!(result1.allowed);
        assert!(result2.allowed);
        assert_eq!(result1.remaining, 1);
        assert_eq!(result2.remaining, 1);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::with_config(RateLimiterConfig {
            capacity: 5,
            window: 1,
            ..Default::default()
        });
        check_capacity_5(&limiter);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(2, 60);
        check_different_ips(&limiter);
    }

    #[cfg(feature = "smol")]
    #[test]
    fn test_rate_limiter() {
        smol::block_on(async {
            let limiter = RateLimiter::with_config(RateLimiterConfig {
                capacity: 5,
                window: 1,
                ..Default::default()
            });
            check_capacity_5(&limiter);
        });
    }

    #[cfg(feature = "smol")]
    #[test]
    fn test_rate_limiter_different_ips() {
        smol::block_on(async {
            let limiter = RateLimiter::new(2, 60);
            check_different_ips(&limiter);
        });
    }

    // Caller must configure the limiter with capacity=1, max_entries=2.
    fn check_overflow_routing(limiter: &RateLimiter) {
        let ip1 = "10.0.0.1".parse::<IpAddr>().unwrap();
        let ip2 = "10.0.0.2".parse::<IpAddr>().unwrap();
        let ip3 = "10.0.0.3".parse::<IpAddr>().unwrap();
        let ip4 = "10.0.0.4".parse::<IpAddr>().unwrap();

        // ip1 and ip2 each get their own bucket (capacity 1).
        assert!(limiter.check_rate_limit(ip1).allowed);
        assert!(limiter.check_rate_limit(ip2).allowed);

        // Map is at capacity; unseen ip3 is routed to the overflow bucket,
        // which is fresh (capacity 1) -> allowed.
        assert!(
            limiter.check_rate_limit(ip3).allowed,
            "first overflow hit should be allowed"
        );
        // ip4 is unseen but shares the now-empty overflow bucket -> denied.
        assert!(
            !limiter.check_rate_limit(ip4).allowed,
            "second overflow hit should be denied"
        );

        // No per-IP buckets were created for ip3/ip4; only the overflow bucket.
        assert!(limiter.map.len() <= 3);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_overflow_bucket() {
        let limiter = RateLimiter::with_config(RateLimiterConfig {
            capacity: 1,
            window: 60,
            max_entries: 2,
            ..Default::default()
        });
        check_overflow_routing(&limiter);
    }

    #[cfg(feature = "smol")]
    #[test]
    fn test_overflow_bucket() {
        smol::block_on(async {
            let limiter = RateLimiter::with_config(RateLimiterConfig {
                capacity: 1,
                window: 60,
                max_entries: 2,
                ..Default::default()
            });
            check_overflow_routing(&limiter);
        });
    }

    #[test]
    #[should_panic(expected = "cleanup_interval must be greater than zero")]
    fn test_zero_cleanup_interval_rejected() {
        // The assertion fires before the cleanup task is spawned, so no runtime
        // is needed and both the tokio and smol paths are covered.
        let _ = RateLimiter::with_config(RateLimiterConfig {
            cleanup_interval: Duration::ZERO,
            ..Default::default()
        });
    }

    #[test]
    fn test_extract_client_ip_trust_proxy() {
        use ntex::web::test::TestRequest;

        // Trusted: X-Forwarded-For is honored.
        let req = TestRequest::default()
            .header("x-forwarded-for", "1.2.3.4")
            .to_srv_request();
        assert_eq!(
            extract_client_ip(&req, true),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );

        // Untrusted (default): XFF is ignored; test requests have no peer
        // address, so we fall back to localhost.
        let req = TestRequest::default()
            .header("x-forwarded-for", "1.2.3.4")
            .to_srv_request();
        assert_eq!(
            extract_client_ip(&req, false),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );

        // Trusted: X-Real-IP is honored.
        let req = TestRequest::default()
            .header("x-real-ip", "5.6.7.8")
            .to_srv_request();
        assert_eq!(
            extract_client_ip(&req, true),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );

        // Trusted but malformed header -> falls back to peer / localhost.
        let req = TestRequest::default()
            .header("x-forwarded-for", "not-an-ip")
            .to_srv_request();
        assert_eq!(
            extract_client_ip(&req, true),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );

        // Trusted but unspecified (`0.0.0.0`) header -> rejected, falls back to
        // peer / localhost, so a client cannot map itself onto OVERFLOW_KEY.
        let req = TestRequest::default()
            .header("x-forwarded-for", "0.0.0.0")
            .to_srv_request();
        assert_eq!(
            extract_client_ip(&req, true),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
