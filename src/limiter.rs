use dashmap::DashMap;
use ntex::http::header::{HeaderName, HeaderValue};
use ntex::{http::StatusCode, Middleware, ServiceCtx};
use std::sync::Arc;

use ntex::{web, Service};
use std::time::{Duration, Instant};

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;
#[cfg(feature = "tokio")]
use tokio::time::interval;

#[cfg(feature = "async-std")]
use async_std::sync::Mutex;
#[cfg(feature = "async-std")]
use async_std::task;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

use crate::util::unix_secs;

const HEADER_RATELIMIT_REMAINING: &str = "x-ratelimit-remaining";
const HEADER_RATELIMIT_LIMIT: &str = "x-ratelimit-limit";
const HEADER_RATELIMIT_RESET: &str = "x-ratelimit-reset";

/// Token bucket algorithm implementation for rate limiting
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
    capacity: usize,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(capacity: usize, window: u64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: unix_secs(),
            capacity,
            refill_rate: capacity as f64 / window as f64,
        }
    }

    fn consume(&mut self, tokens: usize, now: u64) -> bool {
        self.refill(now);
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last_refill) as f64;
        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }

    fn remaining_tokens(&self) -> u32 {
        self.tokens.floor() as u32
    }

    fn reset_time(&self) -> u64 {
        if self.tokens >= self.capacity as f64 {
            unix_secs()
        } else {
            let missing_tokens = self.capacity as f64 - self.tokens;
            let seconds_to_refill = missing_tokens / self.refill_rate;
            self.last_refill + seconds_to_refill.ceil() as u64
        }
    }

    /// Check if this bucket is stale (hasn't been used recently)
    fn is_stale(&self, now: u64, stale_threshold: u64) -> bool {
        now.saturating_sub(self.last_refill) > stale_threshold
    }
}

/// Configuration for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub capacity: usize,
    pub window: u64,
    pub cleanup_interval: Duration,
    pub stale_threshold: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            window: 60,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            stale_threshold: 3600, // 1 hour
        }
    }
}

/// High-performance rate limiter using token bucket algorithm
pub struct RateLimiter {
    map: DashMap<String, TokenBucket>,
    config: RateLimiterConfig,
    last_cleanup: Mutex<Instant>,
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
        let limiter = Arc::new(RateLimiter {
            map: DashMap::new(),
            config,
            last_cleanup: Mutex::new(Instant::now()),
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
    pub fn check_rate_limit(&self, identifier: &str) -> RateLimitResult {
        let now = unix_secs();
        let mut bucket = self
            .map
            .entry(identifier.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.capacity, self.config.window));

        let allowed = bucket.consume(1, now);
        let remaining = bucket.remaining_tokens();
        let reset = bucket.reset_time();

        RateLimitResult {
            allowed,
            remaining,
            reset,
            limit: self.config.capacity,
        }
    }

    /// Clean up stale entries
    async fn cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return;
        }
        *last_cleanup = Instant::now();

        let now = unix_secs();
        let stale_threshold = self.config.stale_threshold;
        
        let initial_size = self.map.len();
        self.map.retain(|_, bucket| !bucket.is_stale(now, stale_threshold));
        let final_size = self.map.len();
        
        if cfg!(debug_assertions) && initial_size > final_size {
            eprintln!("Cleaned {} stale rate limit entries", initial_size - final_size);
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

        let result = self.limiter.check_rate_limit(&ip);

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
fn extract_client_ip<Err>(req: &web::WebRequest<Err>) -> String {
    // Check X-Forwarded-For header first
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            let ip = ip_str.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    // Fallback to connection info
    req.connection_info()
        .remote()
        .unwrap_or("unknown")
        .to_string()
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut ntex::http::HeaderMap, result: &RateLimitResult) {
    if let Ok(value) = HeaderValue::from_str(&result.remaining.to_string()) {
        headers.insert(
            HeaderName::from_static(HEADER_RATELIMIT_REMAINING),
            value,
        );
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
        let mut bucket = TokenBucket::new(5, 10);
        let now = unix_secs();

        // Should allow up to capacity
        for _ in 0..5 {
            assert!(bucket.consume(1, now));
        }

        // Should deny when capacity exceeded
        assert!(!bucket.consume(1, now));
        assert_eq!(bucket.remaining_tokens(), 0);
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 10); // 1 token per second
        let now = unix_secs();

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.consume(1, now));
        }
        assert!(!bucket.consume(1, now));

        // After 5 seconds, should have 5 tokens
        bucket.refill(now + 5);
        assert_eq!(bucket.remaining_tokens(), 5);

        // Should be able to consume 5 tokens
        for _ in 0..5 {
            assert!(bucket.consume(1, now + 5));
        }
        assert!(!bucket.consume(1, now + 5));
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimiterConfig {
            capacity: 5,
            window: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::with_config(config);
        let ip = "192.168.1.1";

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

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(2, 60);

        // Different IPs should have separate limits
        let result1 = limiter.check_rate_limit("192.168.1.1");
        let result2 = limiter.check_rate_limit("192.168.1.2");

        assert!(result1.allowed);
        assert!(result2.allowed);
        assert_eq!(result1.remaining, 1);
        assert_eq!(result2.remaining, 1);
    }
}