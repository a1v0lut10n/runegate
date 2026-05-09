# Make Redis Deployable for Magic-Link-Only Mode

Currently, Runegate's `magic-link-only` mode defaults to an in-memory session store. While a `RedisStore` was scaffolded during earlier architectural changes, it is not wired up. To make Redis genuinely deployable for distributed setups (where multiple Runegate instances need to share session state), we will integrate `actix-session`'s native Redis support.

## User Review Required

- **Rate Limiting**: This plan replaces the core `SessionStore` (which manages OIDC state, CSRF challenges, and authenticated sessions) with Redis. The `RateLimiter` (IP and Email-based limits) will remain an in-memory `Arc<Mutex>` per instance. For typical horizontally scaled deployments behind a load balancer, per-instance rate limiting is usually acceptable. **If you require rate limiting state to also be strictly shared across instances via Redis, please let me know, as that requires a larger rewrite of the rate limiting module.**
- **TLS Configuration**: We will use the `redis-session-rustls` feature so that it inherits the Rustls TLS stack used by the rest of the application.

## Proposed Changes

### Dependencies
#### [MODIFY] Cargo.toml
- Enable the `redis-session-rustls` feature on the `actix-session` dependency to pull in the official `RedisSessionStore`.
- Remove the unused `redis` crate dependency (as `actix-session` manages the Redis connection pool directly for session storage).

### Store Integration
#### [NEW] src/store/session.rs
- Create a `RunegateSessionStore` enum that implements `actix_session::storage::SessionStore`.
- This enum will dynamically dispatch to either `Memory(MemorySessionStore)` or `Redis(actix_session::storage::RedisSessionStore)`. This pattern allows us to use a single type in `SessionMiddleware::builder` without duplicating the massive `HttpServer::new` application builder block in `main.rs`.

#### [DELETE] src/store/redis_store.rs
- Remove the scaffolded `redis_store.rs` file and its module exports, as we will be using `actix-session`'s official Redis implementation instead.

### Application Wiring
#### [MODIFY] src/main.rs
- Check for the `REDIS_URL` environment variable during startup.
- If `REDIS_URL` is set, asynchronously initialize the `RedisSessionStore` and construct `RunegateSessionStore::Redis`.
- If absent, fall back to `RunegateSessionStore::Memory`.
- Pass this dynamic `RunegateSessionStore` into the `SessionMiddleware`.

## Verification Plan

### Automated Tests
- Run `cargo check` and `cargo clippy` to ensure trait bounds and generic signatures for `SessionMiddleware` are satisfied.
- Run `cargo test` to ensure existing rate-limiting and unit tests (which rely on the memory store) remain unbroken.

### Manual Verification
- We can verify the application starts cleanly when `REDIS_URL` is provided (expecting a connection attempt) and falls back cleanly to the memory store when omitted.
