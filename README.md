# ntex-ratelimiter

[![Crates.io](https://img.shields.io/crates/v/ntex-ratelimiter.svg)](https://crates.io/crates/ntex-ratelimiter)
[![Documentation](https://docs.rs/ntex-ratelimiter/badge.svg)](https://docs.rs/ntex-ratelimiter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A rate limiting middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.

## Installation

- `tokio` (default): Enable Tokio runtime support
- `async-std`: Enable async-std runtime support
- `json` (default): Enable JSON serialization for error responses

```toml
[dependencies]
# Default features (tokio + json)
ntex-ratelimiter = "^0"

# With async-std instead of tokio
ntex-ratelimiter = { version = "^0", default-features = false, features = ["async-std", "json"] }

# Minimal build without JSON support
ntex-ratelimiter = { version = "^0", default-features = false, features = ["tokio"] }
```

## Usage

The primary components are `RateLimiter` and `RateLimit`.

- `RateLimiter`: Manages the rate limiting logic and state. You create an instance of this, often shared across your application.
- `RateLimit`: The `ntex` middleware that wraps your services and applies the rate limiting rules defined by a `RateLimiter` instance.

## Quick Start

```rust
use ntex::web;
use ntex_ratelimiter::{RateLimit, RateLimiter};

#[ntex::main]
async fn main() -> std::io::Result<()> {
    // Create a rate limiter: 100 requests per 60 seconds
    let limiter = RateLimiter::new(100, 60);
    
    web::HttpServer::new(move || {
        web::App::new()
            // Apply rate limiting middleware
            .wrap(RateLimit::new(limiter.clone()))
            .service(web::resource("/").to(|| async { "Hello world!" }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Advanced Configuration

For more control over the rate limiter behavior:

```rust
use ntex_ratelimiter::{RateLimiter, RateLimiterConfig};
use std::time::Duration;

let config = RateLimiterConfig {
    capacity: 1000,                              // 1000 requests  
    window: 3600,                               // per hour (3600 seconds)
    cleanup_interval: Duration::from_secs(300), // cleanup every 5 minutes
    stale_threshold: 7200,                      // remove entries idle for 2+ hours
};

let limiter = RateLimiter::with_config(config);

// Get statistics
let stats = limiter.stats();
println!("Active rate limit entries: {}", stats.active_entries);
```

## How It Works

This middleware uses the **token bucket algorithm** for rate limiting:

1. Each client IP gets a token bucket with a configured capacity
1. Tokens are consumed on each request
1. Tokens are refilled at a constant rate based on the time window
1. When the bucket is empty, requests are rate limited

### Client IP Detection

The middleware intelligently extracts client IPs from:

1. `X-Forwarded-For` header (first IP in comma-separated list)
1. `X-Real-IP` header
1. Connection remote address (fallback)

This ensures accurate rate limiting even behind proxies and load balancers.

## Response Headers

The middleware adds these headers to all responses:

|Header                 |Description                                   |
|-----------------------|----------------------------------------------|
|`x-ratelimit-remaining`|Number of requests remaining in current window|
|`x-ratelimit-limit`    |Total request limit for the window            |
|`x-ratelimit-reset`    |Unix timestamp when the rate limit resets     |

## Error Response

When rate limits are exceeded, a `429 Too Many Requests` response is returned:

```json
{
    "code": 429,
    "message": "Rate limit exceeded",
    "data": {
        "remaining": 0,
        "reset": 1700000000,
        "limit": 100
    }
}
```

## Module Structure

- `limiter`: Contains the core `RateLimiter` logic, `TokenBucket` implementation, `RateLimiterConfig`, and the `RateLimit` ntex middleware.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License

MIT All contributor.
