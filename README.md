# ntex-ratelimiter

[![Crates.io](https://img.shields.io/crates/v/ntex-ratelimiter.svg)](https://crates.io/crates/ntex-ratelimiter)
[![Documentation](https://docs.rs/ntex-ratelimiter/badge.svg)](https://docs.rs/ntex-ratelimiter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A rate limiting middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.

## Installation

- `tokio` (default): Enable Tokio runtime support
- `smol`: Enable smol runtime support (smol is the maintained successor of async-std)
- `json` (default): Enable JSON serialization for error responses

```toml
[dependencies]
# Default features (tokio + json)
ntex-ratelimiter = "^0.3"

# With smol instead of tokio
ntex-ratelimiter = { version = "^0.3", default-features = false, features = ["smol", "json"] }

# Minimal build without JSON support
ntex-ratelimiter = { version = "^0.3", default-features = false, features = ["tokio"] }
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
    
    web::HttpServer::new(async move || {
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
    stale_threshold: Duration::from_secs(7200), // remove entries idle for 2+ hours
    trust_proxy_headers: true,                  // trust XFF/X-Real-IP (only behind a trusted proxy)
    max_entries: 100_000,                       // cap tracked IPs; overflow shares a bucket
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

By default the middleware uses only the **peer socket address** — zero-allocation and not spoofable by the client. Set `trust_proxy_headers = true` in `RateLimiterConfig` to also honor proxy headers; do this **only** behind a trusted proxy that overwrites (not appends to) them, since clients can otherwise forge these headers to bypass limiting:

1. `X-Forwarded-For` header (first IP, only when `trust_proxy_headers = true`)
1. `X-Real-IP` header (only when `trust_proxy_headers = true`)
1. Peer socket address (default and fallback)

> ⚠️ **Behind a reverse proxy / load balancer**, leaving `trust_proxy_headers = false` means the peer address is the *proxy's* for every request, so all clients share a single bucket and are throttled together. Set `trust_proxy_headers = true` in that deployment (the proxy must overwrite the headers).

### Memory Safety

The number of tracked client buckets is bounded by `max_entries` (default `100_000`). Once the cap is reached, previously-unseen clients share a single overflow bucket (still rate-limited, and itself counted toward the cap), so an attacker rotating source identifiers — whether real IPs or forged proxy headers — cannot exhaust memory. The bound is best-effort: concurrent requests may transiently exceed it by roughly the number in flight, but never unboundedly.

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
