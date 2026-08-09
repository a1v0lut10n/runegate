// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for the in-process backward-compatibility tests.
// Each test binary compiles this module independently and uses a subset of it.
#![allow(dead_code)]
//!
//! These tests build the real Runegate `App` (the same route table and
//! middleware the binary uses, via `runegate::app::configure_routes`) inside
//! the test process, so no external server, database, Redis, or SMTP relay is
//! needed.

use actix_session::SessionMiddleware;
use actix_web::body::MessageBody;
use actix_web::cookie::{Key, SameSite};
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{App, HttpRequest, HttpResponse, web};
use std::sync::{Arc, Mutex, Once, OnceLock};

use runegate::app::{AppSettings, build_renderer, configure_routes};
use runegate::config::{AppConfig, AuthUiMode, RunegateMode};
use runegate::email::EmailConfig;
use runegate::memory_session_store::MemorySessionStore;
use runegate::middleware::AuthMiddleware;
use runegate::rate_limit::RateLimiters;
use runegate::store::session::RunegateSessionStore;

pub const TEST_JWT_SECRET: &str = "integration-test-jwt-secret-0123456789abcdef";
pub const SESSION_COOKIE: &str = "runegate_id";

static INIT: Once = Once::new();

/// Process-wide env shared by every test in a binary: a fixed JWT secret so
/// tokens can be minted directly, rate limiting off so assertions don't trip
/// per-IP counters, and debug endpoints on for session inspection.
///
/// Deliberately NOT set (this is the "legacy .env" premise): RUNEGATE_MODE,
/// DATABASE_URL, REDIS_URL, RUNEGATE_LOGIN_ASSETS_DIR, RUNEGATE_GOOGLE_*,
/// RUNEGATE_DEFAULT_REDIRECT.
pub fn init_test_env() {
    INIT.call_once(|| unsafe {
        std::env::set_var("RUNEGATE_JWT_SECRET", TEST_JWT_SECRET);
        std::env::set_var("RUNEGATE_RATE_LIMIT_ENABLED", "false");
        std::env::set_var("RUNEGATE_DEBUG_ENDPOINTS", "true");
    });
}

/// Serialises tests that mutate per-request env vars
/// (`RUNEGATE_TARGET_SERVICE`, `RUNEGATE_DEFAULT_REDIRECT`): handlers read
/// them on every request, so concurrent mutation would race.
pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// SMTP config pointing at a closed local port: sending fails immediately
/// with connection refused, exercising the no-SMTP fallback path.
pub fn test_email_config() -> EmailConfig {
    EmailConfig {
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: 1,
        smtp_user: "test@example.com".to_string(),
        smtp_pass: "unused".to_string(),
        from_address: "Runegate Test <test@example.com>".to_string(),
        subject: "Your login link".to_string(),
        body_template: "Login: {login_url} (valid {expiry_minutes} minutes)".to_string(),
    }
}

/// The configuration a published-release deployment would end up with:
/// no OIDC, no upload keys.
pub fn legacy_app_config() -> AppConfig {
    AppConfig {
        base_url: "http://localhost:7870".to_string(),
        email_config: test_email_config(),
        google_oidc: None,
        upload_private_key: None,
        upload_jwks: None,
    }
}

/// Build the real Runegate app for tests, wired exactly like `main.rs`
/// (session middleware → auth middleware → full route table), with an
/// in-memory session store and no PgStore.
pub fn build_test_app(
    mode: RunegateMode,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    init_test_env();

    let settings = AppSettings {
        mode,
        debug_endpoints_enabled: true,
    };
    let session_key = Key::from(&[7u8; 64]);
    let session_store = RunegateSessionStore::Memory(MemorySessionStore::new());
    let rate_limiters = web::Data::new(Arc::new(RateLimiters::new()));
    let renderer = web::Data::from(build_renderer(AuthUiMode::Static));
    let app_config = web::Data::new(legacy_app_config());

    App::new()
        .wrap(AuthMiddleware::with_mode(mode))
        .wrap(
            SessionMiddleware::builder(session_store, session_key)
                .cookie_secure(false)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Lax)
                .cookie_path("/".to_string())
                .cookie_name(SESSION_COOKIE.to_string())
                .build(),
        )
        .app_data(app_config)
        .app_data(rate_limiters)
        .app_data(renderer)
        .app_data(web::Data::new(settings))
        .configure(move |cfg| configure_routes(cfg, &settings))
}

/// Extract the `runegate_id=<value>` pair from a response's Set-Cookie
/// headers, ready to be sent back in a Cookie request header.
pub fn extract_session_cookie<B>(resp: &ServiceResponse<B>) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{}=", SESSION_COOKIE)))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
}

/// Full Set-Cookie header value for the session cookie (for attribute checks).
pub fn raw_session_set_cookie<B>(resp: &ServiceResponse<B>) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{}=", SESSION_COOKIE)))
        .map(|v| v.to_string())
}

async fn echo_upstream(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let headers: std::collections::HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({
        "upstream": true,
        "path": req.path(),
        "method": req.method().as_str(),
        "body_len": body.len(),
        "headers": headers,
    }))
}

/// Spawn a real HTTP upstream that echoes the request it received; point
/// `RUNEGATE_TARGET_SERVICE` at `.url("")` while holding `env_lock()`.
pub fn spawn_upstream() -> actix_test::TestServer {
    actix_test::start(|| App::new().default_service(web::route().to(echo_upstream)))
}

/// Set RUNEGATE_TARGET_SERVICE to the given upstream (call under env_lock()).
pub fn point_proxy_at(srv: &actix_test::TestServer) {
    let url = srv.url("");
    let url = url.trim_end_matches('/');
    unsafe { std::env::set_var("RUNEGATE_TARGET_SERVICE", url) };
}
