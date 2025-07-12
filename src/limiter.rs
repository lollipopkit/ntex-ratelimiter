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

use crate::util::unix_secs;

const HEADER_RATELIMIT_REMAINING: &str = "lk-ratelimit-remaining";
const HEADER_RATELIMIT_LIMIT: &str = "lk-ratelimit-limit";

// Token bucket algorithm for rate limiting
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
    capacity: usize,
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: usize, window: u64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: unix_secs(),
            capacity,
            refill_rate: capacity as f64 / window as f64, // tokens per second
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

    fn tokens_remaining(&self) -> u32 {
        self.tokens.floor() as u32
    }

    fn reset_time(&self) -> u64 {
        if self.tokens >= self.capacity as f64 {
            0
        } else {
            let missing_tokens = self.capacity as f64 - self.tokens;
            let seconds_to_refill = missing_tokens / self.refill_rate;
            self.last_refill + seconds_to_refill.ceil() as u64
        }
    }
}

pub struct RateLimiter {
    map: DashMap<String, TokenBucket>,
    capacity: usize,
    window: u64,
    last_cleanup: Mutex<Instant>,
    cleanup_interval: Duration,
}

impl RateLimiter {
    pub fn new(capacity: usize, window: u64) -> Arc<Self> {
        let limiter = Arc::new(RateLimiter {
            map: DashMap::new(),
            capacity,
            window,
            last_cleanup: Mutex::new(Instant::now()),
            cleanup_interval: Duration::from_secs(60),
        });

        // Start periodic cleanup if a runtime is enabled
        #[cfg(any(feature = "tokio", feature = "async-std"))]
        Self::start_cleanup_task(Arc::clone(&limiter));

        limiter
    }

    #[cfg(feature = "tokio")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter.clean().await;
            }
        });
    }

    #[cfg(feature = "async-std")]
    fn start_cleanup_task(limiter: Arc<RateLimiter>) {
        task::spawn(async move {
            loop {
                task::sleep(Duration::from_secs(60)).await;
                limiter.clean().await;
            }
        });
    }

    fn check_rate_limit(&self, ip: &str) -> (bool, u32, Option<u64>) {
        let now = unix_secs();
        let mut bucket = self
            .map
            .entry(ip.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.window));

        let allowed = bucket.consume(1, now);
        let remaining = bucket.tokens_remaining();
        let reset = if !allowed {
            Some(bucket.reset_time())
        } else {
            None
        };

        (allowed, remaining, reset)
    }

    async fn clean(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        if last_cleanup.elapsed() < self.cleanup_interval {
            return;
        }
        *last_cleanup = Instant::now();

        let now = unix_secs();
        self.map.retain(|_, bucket| {
            bucket.refill(now);
            now - bucket.last_refill < self.window * 2
        });
    }
}

pub struct RateLimit {
    pub limiter: Arc<RateLimiter>,
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
        let ip = match req.headers().get("x-forwarded-for").map(|forwarded| {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(ip) = forwarded_str.split(',').next() {
                    return Some(ip.trim().to_string());
                }
            }
            // Fallback to the remote address if x-forwarded-for is not present
            req.connection_info().remote().map(|s| s.to_string())
        }).flatten() {
            Some(ip) => ip,
            None => {
                return Err(web::error::ErrorBadRequest("Invalid IP").into())
            }
        };

        let (allowed, remaining, reset) = self.limiter.check_rate_limit(&ip);

        if !allowed {
            Err(RateLimitErr {
                remaining,
                reset: reset.unwrap_or(0),
                limit: self.limiter.capacity,
            }
            .into())
        } else {
            let mut res = ctx.call(&self.service, req).await?;

            // Add rate limit headers to successful responses
            if let Ok(header_value) = HeaderValue::from_str(&remaining.to_string()) {
                let header_name = HeaderName::from_static(HEADER_RATELIMIT_REMAINING);
                res.headers_mut().insert(header_name, header_value);
            }
            if let Ok(header_value) = HeaderValue::from_str(&self.limiter.capacity.to_string()) {
                let header_name = HeaderName::from_static(HEADER_RATELIMIT_LIMIT);
                res.headers_mut().insert(header_name, header_value);
            }

            Ok(res)
        }
    }
}

#[derive(Debug)]
struct RateLimitErr {
    remaining: u32,
    reset: u64,
    limit: usize,
}

impl std::fmt::Display for RateLimitErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded. Remaining: {}, Reset: {}",
            self.remaining, self.reset
        )
    }
}

impl web::error::WebResponseError for RateLimitErr {
    fn error_response(&self, _: &ntex::web::HttpRequest) -> web::HttpResponse {
        let body = format!(
            r#"
{{
    "code": 5,
    "msg": "Rate limit",
    "data": {{
        "remaining": {},
        "reset": {},
        "limit": {}
    }}
}}"#,
            self.remaining, self.reset, self.limit
        );

        web::HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
            .set_header("content-type", "application/json")
            .set_header(HEADER_RATELIMIT_REMAINING, self.remaining.to_string())
            .set_header(HEADER_RATELIMIT_LIMIT, self.limit.to_string())
            .body(body)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let n = 20;
        let window = 1;
        let ip = "127.0.0.1";
        let limiter = RateLimiter::new(n, window);

        for _ in 0..n {
            let (allowed, remaining, _) = limiter.check_rate_limit(ip);
            assert!(allowed);
            assert!(remaining < n as u32);
        }

        let (allowed, remaining, reset) = limiter.check_rate_limit(ip);
        assert!(!allowed);
        assert_eq!(remaining, 0);
        assert!(reset.is_some());

        std::thread::sleep(std::time::Duration::from_secs(window + 1));

        let (allowed, remaining, _) = limiter.check_rate_limit(ip);
        assert!(allowed);
        assert!(remaining > 0);
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 60);
        let now = unix_secs();

        // 消耗所有token
        for _ in 0..10 {
            assert!(bucket.consume(1, now));
        }
        assert!(!bucket.consume(1, now));

        // 等待一秒后应该有新的token
        assert!(bucket.consume(1, now + 60));
    }
}
