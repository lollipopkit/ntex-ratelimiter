//! # ntex-ratelimiter
//!
//! `ntex-ratelimiter` is a rate limiting middleware for the `ntex` web framework.
//! It uses the token bucket algorithm to limit the number of requests from clients
//! based on their IP address.
//!
//! ## Features
//!
//! - **Token Bucket Algorithm**: Efficiently manages request rates.
//! - **IP-based Rate Limiting**: Identifies clients by IP address.
//! - **Spoofing-Resistant**: Defaults to the unspoofable peer socket address; `X-Forwarded-For` / `X-Real-IP` are opt-in via `trust_proxy_headers`.
//! - **Bounded Memory**: A `max_entries` cap routes excess unseen clients to a shared overflow bucket, so rotating-IP attacks cannot exhaust memory.
//! - **Configurable**: Capacity, time window, cleanup interval, proxy-header trust, and max entries.
//! - **Asynchronous Cleanup**: Periodically removes stale rate limit entries to save memory.
//! - **Response Headers**: Adds `X-RateLimit-Remaining`, `X-RateLimit-Limit`, and `X-RateLimit-Reset` headers to responses.
//! - **Customizable Error Response**: Returns a `429 Too Many Requests` JSON response when limits are exceeded.
//! - **Runtime Agnostic**: Supports both `tokio` (default) and `smol` runtimes via feature flags.
//!
//! ## Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ntex-ratelimiter = "^0.3.0"
//! ```
//!
//! ## Feature Flags
//!
//! - `tokio` (default): Enables Tokio runtime support.
//! - `smol`: Enables smol runtime support (smol is the maintained successor of async-std).
//! - `json` (default): Enables JSON serialization for error responses using `serde`.
//!
//! Example with `smol` and `json`:
//! ```toml
//! [dependencies]
//! ntex-ratelimiter = { version = "^0.3.0", default-features = false, features = ["smol", "json"] }
//! ```
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ntex::web;
//! use ntex_ratelimiter::{RateLimit, RateLimiter};
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     // Create a rate limiter: 100 requests per 60 seconds
//!     let limiter = RateLimiter::new(100, 60);
//!     
//!     web::HttpServer::new(async move || {
//!         web::App::new()
//!             // Apply rate limiting middleware
//!             .wrap(RateLimit::new(limiter.clone()))
//!             .service(web::resource("/").to(|| async { "Hello world!" }))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! For more advanced usage and configuration, please refer to the documentation of
//! [`RateLimiter`] and [`RateLimiterConfig`].
//!
//! ## Module Structure
//!
//! - `limiter`: Contains the core rate limiting logic, including the `RateLimiter` struct,
//!   `RateLimiterConfig`, `TokenBucket` implementation, and the `RateLimit` ntex middleware.

mod limiter;

pub use limiter::{RateLimit, RateLimitResult, RateLimiter, RateLimiterConfig, RateLimiterStats};

// Prevent conflicting runtime features
#[cfg(all(feature = "tokio", feature = "smol"))]
compile_error!("Features \"tokio\" and \"smol\" cannot be enabled at the same time.");

#[cfg(not(any(feature = "tokio", feature = "smol")))]
compile_error!("Enable either feature \"tokio\" or \"smol\" for ntex-ratelimiter to work.");

#[cfg(feature = "tokio")]
pub use tokio;

#[cfg(feature = "smol")]
pub use smol;
