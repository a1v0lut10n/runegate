// SPDX-License-Identifier: Apache-2.0
//! Backward-compatibility contract for magic-link-only mode.
//!
//! Premise: a deployment running the published v0.3.x release upgrades to this
//! version with its `.env` unchanged — no `RUNEGATE_MODE`, no `DATABASE_URL`,
//! no `REDIS_URL`, no Google OIDC settings, assets in the CWD-relative
//! `static/` directory. Every test asserts behaviour that release documented
//! or shipped. See docs/howto/magic-link-only-mode.md.
// Tests deliberately hold the env mutex across awaits to serialise env mutation.
#![allow(clippy::await_holding_lock)]

mod common;

use actix_web::http::{StatusCode, header};
use actix_web::test;
use common::*;
use runegate::auth::{create_token, get_magic_link_expiry};
use runegate::config::RunegateMode;
use serde::Serialize;

fn location<B>(resp: &actix_web::dev::ServiceResponse<B>) -> &str {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[actix_web::test]
async fn health_endpoint_unchanged() {
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "running");
    assert_eq!(body["service"], "Runegate");
}

#[actix_web::test]
async fn login_page_served_from_repo_static_dir() {
    // v0.3.x served static/login.html relative to the working directory; a
    // legacy deployment must not need RUNEGATE_LOGIN_ASSETS_DIR to get it.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    for uri in ["/login.html", "/auth/login", "/auth/login.html"] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET {} should serve login page",
            uri
        );
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/html"),
            "GET {}: content-type was {}",
            uri,
            ct
        );
        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("email"), "GET {}: not the login form", uri);
    }
}

#[actix_web::test]
async fn root_requires_auth_in_magic_link_mode() {
    // The highest-value assertion in the suite: on v0.3.x, `/` redirected an
    // unauthenticated visitor to the login page. The gateway-mode public
    // landing page must not leak into magic-link-only deployments.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/login.html");
}

#[actix_web::test]
async fn favicons_and_app_assets_require_auth_in_magic_link_mode() {
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    for uri in ["/favicon.ico", "/favicon.svg", "/_app/immutable/entry.js"] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "GET {} must stay gated",
            uri
        );
        assert_eq!(location(&resp), "/login.html", "GET {}", uri);
    }
}

#[actix_web::test]
async fn protected_path_redirects_to_login_not_mfa() {
    // Guards the new PREAUTH → /mfa middleware branch: an anonymous request
    // must follow the v0.3.x redirect to /login.html, never /mfa.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/some/protected/path")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/login.html");
}

#[actix_web::test]
async fn post_login_alias_returns_ok_with_smtp_down() {
    // Legacy alias POST /login must still reach magic_start. NOTE: this branch
    // deliberately returns 200 and logs the link when SMTP is unreachable
    // (commit 66f116a); v0.3.x returned 500. Pinned here so a future change is
    // a conscious one — see the implementation plan for the caveat.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/login")
            .set_json(serde_json::json!({"email": "user@example.com"}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn magic_link_roundtrip_establishes_legacy_session() {
    let _guard = env_lock(); // asserts the RUNEGATE_DEFAULT_REDIRECT default
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;

    let email = "roundtrip@example.com";
    let token = create_token(email, get_magic_link_expiry(), "test-jti").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;

    // v0.3.x contract: 302 to /proxy/ with a hardened host-only session cookie
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/proxy/");
    let raw = raw_session_set_cookie(&resp).expect("session cookie must be set");
    assert!(raw.contains("HttpOnly"), "cookie must be HttpOnly: {}", raw);
    assert!(
        raw.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax: {}",
        raw
    );
    assert!(raw.contains("Path=/"), "cookie path must be /: {}", raw);
    assert!(
        !raw.contains("Domain="),
        "cookie must stay host-only: {}",
        raw
    );
    assert!(
        !raw.contains("Secure"),
        "no Secure flag outside production: {}",
        raw
    );

    // The session must be fully authenticated (not stuck in PREAUTH)
    let cookie = extract_session_cookie(&resp).unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/debug/session")
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["email"], email);
}

/// The claim set minted by the published v0.3.x release: no `jti`.
#[derive(Serialize)]
struct LegacyClaims {
    sub: String,
    exp: usize,
    iat: usize,
}

#[actix_web::test]
async fn v03x_token_without_jti_still_accepted() {
    // An in-flight magic link minted seconds before the upgrade must still log
    // its user in afterwards.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = LegacyClaims {
        sub: "legacy@example.com".to_string(),
        exp: now + 900,
        iat: now,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "legacy token must still authenticate"
    );
    assert!(extract_session_cookie(&resp).is_some());
}

#[actix_web::test]
async fn invalid_or_missing_token_rejected() {
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth?token=garbage")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = test::call_service(&app, test::TestRequest::get().uri("/auth").to_request()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn authenticated_request_proxied_with_identity_headers() {
    let _guard = env_lock();
    let upstream = spawn_upstream();
    point_proxy_at(&upstream);

    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let email = "proxied@example.com";
    let token = create_token(email, get_magic_link_expiry(), "jti-proxy").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&resp).unwrap();

    // Client-supplied identity headers must be stripped, session identity injected
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/some/app/page")
            .insert_header((header::COOKIE, cookie.clone()))
            .insert_header(("X-User-Id", "spoofed"))
            .insert_header(("X-Forwarded-User", "spoofed"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["upstream"], true);
    assert_eq!(body["path"], "/some/app/page");
    let headers = &body["headers"];
    // v0.3.x header set
    assert_eq!(headers["x-runegate-authenticated"], "true");
    assert_eq!(headers["x-runegate-user"], email);
    assert_eq!(headers["x-forwarded-user"], email);
    assert_eq!(headers["x-forwarded-email"], email);
    // Additive on this branch; note X-User-Id carries the EMAIL, not an id
    assert_eq!(headers["x-user-id"], email);
    assert_eq!(headers["x-user-email"], email);
    // Session cookie must not leak upstream
    let fwd_cookies = headers["cookie"].as_str().unwrap_or("");
    assert!(
        !fwd_cookies.contains(SESSION_COOKIE),
        "session cookie leaked: {}",
        fwd_cookies
    );

    // /proxy/* prefix still maps to the target root
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/proxy/hello")
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["path"], "/hello");
}

#[actix_web::test]
async fn default_redirect_env_still_honoured() {
    let _guard = env_lock();
    unsafe { std::env::set_var("RUNEGATE_DEFAULT_REDIRECT", "/app") };
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let token = create_token("redirect@example.com", get_magic_link_expiry(), "jti-r").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    unsafe { std::env::remove_var("RUNEGATE_DEFAULT_REDIRECT") };
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/app");
}

#[actix_web::test]
async fn authenticated_user_on_login_page_redirected_to_default_target() {
    // New on this branch: an already-authenticated user hitting the login page
    // is bounced onward. The target must follow RUNEGATE_DEFAULT_REDIRECT
    // (here unset → the historical /proxy/), not a hardcoded /app.
    let _guard = env_lock();
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let token = create_token("logged-in@example.com", get_magic_link_expiry(), "jti-l").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&resp).unwrap();

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/login.html")
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/proxy/");
}

#[actix_web::test]
async fn gateway_only_endpoints_degrade_cleanly_without_their_config() {
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;

    // Google OIDC unconfigured: pinned as a stable 5xx with a clear message
    // (not a panic, not an actix extraction error). 503 would be nicer; if
    // that changes, update this pin deliberately.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/google/start")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = test::read_body(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("not configured"));

    // Admin API: /admin/* is not a public path, so an anonymous call gets the
    // same login redirect any unknown path got on v0.3.x — never a 500
    // "app data not configured" extraction error.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/admin/invites")
            .set_json(serde_json::json!({"max_uses": 1}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/login.html");
}

#[actix_web::test]
async fn upload_ticket_disabled_without_keys() {
    // docs/howto/magic-link-only-mode.md: edge authorization is "disabled" in
    // this mode — the endpoint answers 501, it does not 500.
    let app = test::init_service(build_test_app(RunegateMode::MagicLinkOnly)).await;
    let token = create_token("uploader@example.com", get_magic_link_expiry(), "jti-u").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&resp).unwrap();

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/upload-ticket")
            .insert_header((header::COOKIE, cookie))
            .set_json(serde_json::json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
