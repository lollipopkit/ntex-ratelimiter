# ntex-ratelimiter

A flexible rate limiting middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.

## Features

- 🚀 High-performance, thread-safe rate limiting
- 🪣 Token bucket algorithm for precise rate control
- 🔄 Automatic cleanup of expired rate limiters
- 🧩 Simple integration with ntex applications
- ⚙️ Runtime support for both tokio and async-std via feature flags
- 📊 Rate limit headers included in responses
- ✅ Well-tested and production-ready

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ntex-ratelimiter = "0.1.0"
```

With async runtime features:

```toml
[dependencies]
ntex-ratelimiter = { version = "0.1.0", features = ["tokio"] }
# or
ntex-ratelimiter = { version = "0.1.0", features = ["async-std"] }
```

## Usage

```rust
use ntex::{web, App, HttpServer};
use ntex_ratelimiter::{RateLimit, RateLimiter};
use std::sync::Arc;

#[ntex::main]
async fn main() -> std::io::Result<()> {
    // Create a rate limiter with 100 requests per 60 seconds
    let limiter = RateLimiter::new(100, 60);
    
    HttpServer::new(move || {
        App::new()
            // Apply rate limiting middleware
            .wrap(RateLimit { limiter: Arc::clone(&limiter) })
            .service(web::resource("/").to(|| async { "Hello world!" }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration

The `RateLimiter::new()` function takes two parameters:

- `capacity`: The maximum number of requests allowed in the time window
- `window`: The time window in seconds

## Response Headers

When rate limiting is active, the following headers are added to responses:

- `lk-ratelimit-remaining`: The number of requests remaining in the current window
- `lk-ratelimit-limit`: The total request limit for the window

## Error Response

When rate limits are exceeded, a `429 Too Many Requests` status code is returned with a JSON response:

```json
{
    "code": 5,
    "msg": "Rate limit",
    "remaining": 0,
    "reset": 1621234567,
    "limit": 100
}
```

- `remaining`: Always 0 when limit is exceeded
- `reset`: Unix timestamp when the rate limit will reset
- `limit`: The configured request limit

## Advanced Usage

### Custom Rate Limiter Configuration

```rust
use ntex_ratelimiter::{RateLimit, RateLimiter};
use std::sync::Arc;
use std::time::Duration;

// Create a custom rate limiter with 200 requests per 30 seconds
let limiter = RateLimiter::new(200, 30);

// Use the rate limiter in your middleware
let rate_limit = RateLimit { limiter: Arc::clone(&limiter) };
```

## License
`MIT lollipopkit`