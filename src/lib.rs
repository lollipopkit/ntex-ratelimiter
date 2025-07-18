//! # ntex-ratelimiter
//!
//! `ntex-ratelimiter` is a rate limiting middleware for the `ntex` web framework.
//! It uses the token bucket algorithm to limit the number of requests from clients
//! based on their IP address.
//!
//! ## Features
//!
//! - **Token Bucket Algorithm**: Efficiently manages request rates.
//! - **IP-based Rate Limiting**: Identifies clients by IP address, with support for `X-Forwarded-For` and `X-Real-IP` headers.
//! - **Configurable**: Allows customization of capacity, time window, and cleanup intervals.
//! - **Asynchronous Cleanup**: Periodically removes stale rate limit entries to save memory.
//! - **Response Headers**: Adds `X-RateLimit-Remaining`, `X-RateLimit-Limit`, and `X-RateLimit-Reset` headers to responses.
//! - **Customizable Error Response**: Returns a `429 Too Many Requests` JSON response when limits are exceeded.
//! - **Runtime Agnostic**: Supports both `tokio` (default) and `async-std` runtimes via feature flags.
//!
//! ## Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ntex-ratelimiter = "^0.1.0"
//! ```
//!
//! ## Feature Flags
//!
//! - `tokio` (default): Enables Tokio runtime support.
//! - `async-std`: Enables async-std runtime support.
//! - `json` (default): Enables JSON serialization for error responses using `serde`.
//!
//! Example with `async-std` and `json`:
//! ```toml
//! [dependencies]
//! ntex-ratelimiter = { version = "^0.1.0", default-features = false, features = ["async-std", "json"] }
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
//!     web::HttpServer::new(move || {
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
#[cfg(all(feature = "tokio", feature = "async-std"))]
compile_error!("Features \"tokio\" and \"async-std\" cannot be enabled at the same time.");

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("Enable either feature \"tokio\" or \"async-std\" for ntex-ratelimiter to work.");

#[cfg(feature = "tokio")]
pub use tokio;

#[cfg(feature = "async-std")]
pub use async_std;
