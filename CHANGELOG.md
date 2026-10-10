# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-10

### Breaking

- `RateLimiter` is generic over its key: `RateLimiter<K = IpAddr>`, with
  `K: Hash + Eq + Clone`. Existing IP-based code keeps compiling through type
  inference.
- The `tokio` and `smol` features and their dependencies are removed, along
  with the `ntex_ratelimiter::tokio` / `ntex_ratelimiter::smol` re-exports.
  The background cleanup task is replaced by inline cleanup (see Changed), so
  the crate no longer depends on an async runtime and works on every ntex
  runtime. Previously, constructing a limiter outside a tokio runtime (e.g.
  with ntex on neon or compio) panicked.
- `RateLimiter::check_rate_limit` takes the key by reference
  (`&K` instead of `IpAddr`). The key is cloned only when a new bucket is
  inserted.
- The overflow bucket is a dedicated field instead of a `0.0.0.0` entry in the
  map. It is no longer counted toward `max_entries` (at most
  `max_entries + 1` buckets), and `stats().active_entries` no longer includes
  it.
- Requests without a peer address (e.g. on a Unix socket listener) are charged
  to the shared overflow bucket instead of a `127.0.0.1` bucket, so they no
  longer share a bucket with genuine local requests.
- `RateLimiterConfig::trust_proxy_headers: bool` is replaced by
  `trusted_proxies: Vec<IpNet>`. `X-Forwarded-For` is read only when the peer
  is in one of these networks, and the client IP is the rightmost hop that is
  not a trusted proxy (previously the leftmost hop, which a client can forge
  when the proxy appends to the header).
- `X-Real-IP` is no longer read.
- IPv6 clients are keyed by their `/64` prefix by default
  (`RateLimiterConfig::ipv6_prefix_len`).
- `RateLimiterConfig::stale_threshold` is removed. Cleanup now reclaims
  buckets that have refilled to full capacity, which is lossless; memory for
  an idle key is released after about `window + cleanup_interval`.
- The `json` feature and the `serde` / `serde_json` dependencies are removed.
  The 429 response body is unchanged.
- `RateLimitResult` has a new public field `retry_after`, so constructing it
  with a struct literal requires the new field.
- `RateLimiter::with_config` panics when `capacity` is `0` or
  `ipv6_prefix_len` is greater than `128`.

### Added

- `RateLimit::with_key(limiter, key_fn)`: middleware keyed by
  `Fn(&WebRequest<Err>) -> Option<K>`. Requests for which `key_fn` returns
  `None` are not rate-limited.
- `KeyExtractor<K, Err>` trait and the default `PeerIp` extractor.
- `RateLimitResult::retry_after`: seconds until the next request is allowed.
- 429 responses include a `Retry-After` header.
- `IpNet` is re-exported from `ipnet`.
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to IPv4, both
  for the key and for `trusted_proxies` matching.
- `X-Forwarded-For` hops may carry a port (`1.2.3.4:80`, `[::1]:80`), and
  multiple header lines are read as one list.
- README example for limiting by API token in a handler.
- GitHub Actions CI (test, clippy, doc).

### Changed

- Cleanup runs inline: the first `check_rate_limit` call after each
  `cleanup_interval` reclaims full buckets, with a CAS so only one caller per
  interval does it. `RateLimiter::cleanup()` is public for manual scheduling.
- `stats().active_entries` reads an atomic counter instead of locking every
  map shard.

### Removed

- Debug-build `eprintln!` in the cleanup task.

### Migration

```rust
// 0.3
limiter.check_rate_limit(ip);
RateLimiterConfig {
    trust_proxy_headers: true,
    stale_threshold: Duration::from_secs(3600),
    ..Default::default()
};

// 0.4
limiter.check_rate_limit(&ip);
RateLimiterConfig {
    trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
    ..Default::default()
};
```

Remove `default-features` / `features` from the dependency; the crate has no
features.

## [0.3.0] - 2026-07-15

### Breaking

- Upgraded to ntex 3 (`Middleware::create` takes `SharedCfg`;
  `HttpServer::new` takes an async closure).
- Replaced async-std (discontinued, RUSTSEC-2025-0052) with smol.
- Proxy headers (`X-Forwarded-For` / `X-Real-IP`) are no longer trusted by
  default; opt in via `RateLimiterConfig::trust_proxy_headers`.

### Added

- `RateLimiterConfig::max_entries`: caps tracked clients; unseen clients
  share an overflow bucket once the cap is reached.

### Fixed

- Rate-limit bypass via forged proxy headers.
- Unbounded memory growth under rotating client IPs.
- Cleanup task kept the limiter alive forever; it now holds a weak reference.
- Cleanup stalled on wall-clock rollback.
- Zero `cleanup_interval` is rejected.

### Changed

- Client IP from `peer_addr()` instead of a `connection_info()` string
  round-trip; rate-limit headers formatted with `itoa`; narrower shard lock
  in `check_rate_limit`.

## [0.2.1] - 2025-11-25

### Fixed

- Validate that `window` is greater than zero; tidy token bucket reset.

[Unreleased]: https://github.com/lollipopkit/ntex-ratelimiter/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lollipopkit/ntex-ratelimiter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lollipopkit/ntex-ratelimiter/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/lollipopkit/ntex-ratelimiter/releases/tag/v0.2.1
