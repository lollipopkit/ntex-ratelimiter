use dashmap::DashMap;
use ntex::http::header::{HeaderName, HeaderValue};
use ntex::{http::StatusCode, Middleware, ServiceCtx};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ntex::{web, Service};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use tokio::time::interval;

#[cfg(feature = "async-std")]
use async_std::task;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

const HEADER_RATELIMIT_REMAINING: &str = "x-ratelimit-remaining";
const HEADER_RATELIMIT_LIMIT: &str = "x-ratelimit-limit";
const HEADER_RATELIMIT_RESET: &str = "x-ratelimit-reset";

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

    fn remaining_tokens(&self) -> u32 {
        self.tokens.floor() as u32
    }

    fn reset_time(&self, _now: Instant, config: &RateLimiterConfig) -> u64 {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.tokens >= config.capacity as f64 {
            return now_secs;
        }

        let missing_tokens = config.capacity as f64 - self.tokens;
        let refill_rate = config.capacity as f64 / config.window as f64;
        let seconds_to_refill = missing_tokens / refill_rate;

        now_secs + seconds_to_refill.ceil() as u64
    }

    /// Check if this bucket is stale (hasn't been used recently)
    fn is_stale(&self, now: Instant, stale_threshold: Duration) -> bool {
        now.duration_since(self.last_refill) > stale_threshold
    }
}

/// Configuration for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub capacity: usize,
    pub window: u64,
    pub cleanup_interval: Duration,
    pub stale_threshold: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            window: 60,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            stale_threshold: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// High-performance rate limiter using token bucket algorithm
pub struct RateLimiter {
    map: DashMap<IpAddr, TokenBucket>,
    config: RateLimiterConfig,
    last_cleanup: AtomicU64,
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

        let limiter = Arc::new(RateLimiter {
            map: DashMap::new(),
            config,
            last_cleanup: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        });

        // Start periodic cleanup if a runtime is enabled
        #[cfg(any(feature = "tokio", feature = "async-std"))]
        Self::start_cleanup_task(Arc::clone(&limiter));

        limiter
    }

    #[cfg(feature = "tokio")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
        tokio::spawn(async move {
            let mut interval = interval(limiter.config.cleanup_interval);
            loop {
                interval.tick().await;
                limiter.cleanup().await;
            }
        });
    }

    #[cfg(feature = "async-std")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
        let cleanup_interval = limiter.config.cleanup_interval;
        task::spawn(async move {
            loop {
                task::sleep(cleanup_interval).await;
                limiter.cleanup().await;
            }
        });
    }

    /// Check rate limit for a given identifier (usually IP address)
    pub fn check_rate_limit(&self, identifier: IpAddr) -> RateLimitResult {
        let now = Instant::now();
        let mut bucket = self
            .map
            .entry(identifier)
            .or_insert_with(|| TokenBucket::new(self.config.capacity));

        let allowed = bucket.consume(1, now, &self.config);
        let remaining = bucket.remaining_tokens();
        let reset = bucket.reset_time(now, &self.config);

        RateLimitResult {
            allowed,
            remaining,
            reset,
            limit: self.config.capacity,
        }
    }

    /// Clean up stale entries
    async fn cleanup(&self) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_cleanup = self.last_cleanup.load(Ordering::Acquire);

        // Check if enough time has passed since last cleanup
        if now_secs.saturating_sub(last_cleanup) < self.config.cleanup_interval.as_secs() {
            return;
        }

        // Try to update the last cleanup time atomically
        if self
            .last_cleanup
            .compare_exchange(last_cleanup, now_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            // Another thread is doing cleanup, skip this one
            return;
        }

        let now = Instant::now();
        let stale_threshold = self.config.stale_threshold;

        let initial_size = self.map.len();
        self.map
            .retain(|_, bucket| !bucket.is_stale(now, stale_threshold));
        let final_size = self.map.len();

        if cfg!(debug_assertions) && initial_size > final_size {
            eprintln!(
                "Cleaned {} stale rate limit entries",
                initial_size - final_size
            );
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

impl<S> Middleware<S> for RateLimit {
    type Service = RateLimitMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
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
        let ip = extract_client_ip(&req);

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

/// Extract client IP from request, considering proxy headers
fn extract_client_ip<Err>(req: &web::WebRequest<Err>) -> IpAddr {
    // Check X-Forwarded-For header first
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                let ip = ip.trim();
                if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                    return parsed_ip;
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            let ip = ip_str.trim();
            if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                return parsed_ip;
            }
        }
    }

    // Fallback to connection info - parse SocketAddr to get IP only
    if let Some(addr_str) = req.connection_info().remote() {
        if let Ok(sock_addr) = addr_str.parse::<std::net::SocketAddr>() {
            return sock_addr.ip();
        }
    }

    // Default to localhost if all else fails
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut ntex::http::HeaderMap, result: &RateLimitResult) {
    if let Ok(value) = HeaderValue::from_str(&result.remaining.to_string()) {
        headers.insert(HeaderName::from_static(HEADER_RATELIMIT_REMAINING), value);
    }
    if let Ok(value) = HeaderValue::from_str(&result.limit.to_string()) {
        headers.insert(HeaderName::from_static(HEADER_RATELIMIT_LIMIT), value);
    }
    if let Ok(value) = HeaderValue::from_str(&result.reset.to_string()) {
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

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
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
        let error_response = RateLimitErrorResponse {
            code: 429,
            message: "Rate limit exceeded".to_string(),
            data: RateLimitErrorData {
                remaining: self.data.remaining,
                reset: self.data.reset,
                limit: self.data.limit,
            },
        };

        #[cfg(feature = "json")]
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"code":429,"message":"Rate limit exceeded"}"#.to_string());

        #[cfg(not(feature = "json"))]
        let body = format!(
            r#"{{"code":429,"message":"Rate limit exceeded","data":{{"remaining":{},"reset":{},"limit":{}}}}}"#,
            self.data.remaining, self.data.reset, self.data.limit
        );

        web::HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
            .set_header("content-type", "application/json")
            .set_header(HEADER_RATELIMIT_REMAINING, self.data.remaining.to_string())
            .set_header(HEADER_RATELIMIT_LIMIT, self.data.limit.to_string())
            .set_header(HEADER_RATELIMIT_RESET, self.data.reset.to_string())
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
        assert_eq!(bucket.remaining_tokens(), 0);
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
        assert_eq!(bucket.remaining_tokens(), 5);

        // Should be able to consume 5 tokens
        for _ in 0..5 {
            assert!(bucket.consume(1, later, &config));
        }
        assert!(!bucket.consume(1, later, &config));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimiterConfig {
            capacity: 5,
            window: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
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

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(2, 60);

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
}
