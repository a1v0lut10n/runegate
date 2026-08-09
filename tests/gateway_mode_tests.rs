// SPDX-License-Identifier: Apache-2.0
//! Gateway-mode counterpart to the backward-compat suite: with
//! `RUNEGATE_MODE=gateway` (verbatime's configuration) the public landing
//! page behaviour introduced on this branch must keep working, while
//! everything else stays gated.
// Tests deliberately hold the env mutex across awaits to serialise env mutation.
#![allow(clippy::await_holding_lock)]

mod common;

use actix_web::http::{StatusCode, header};
use actix_web::test;
use common::*;
use runegate::auth::{create_token, get_magic_link_expiry};
use runegate::config::RunegateMode;

fn location<B>(resp: &actix_web::dev::ServiceResponse<B>) -> &str {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[actix_web::test]
async fn gateway_root_and_assets_are_public_and_proxied() {
    let _guard = env_lock();
    let upstream = spawn_upstream();
    point_proxy_at(&upstream);

    let app = test::init_service(build_test_app(RunegateMode::Gateway)).await;

    for uri in ["/", "/favicon.ico", "/_app/immutable/entry.js"] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET {} should proxy without auth",
            uri
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["upstream"], true);
        // Anonymous public traffic is marked as such for the fronted app
        assert_eq!(body["headers"]["x-runegate-authenticated"], "false");
    }
}

#[actix_web::test]
async fn gateway_protected_paths_still_redirect_to_login() {
    let app = test::init_service(build_test_app(RunegateMode::Gateway)).await;
    for uri in ["/app", "/p/123", "/new", "/api/projects"] {
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
async fn gateway_magic_link_roundtrip_unaffected() {
    let _guard = env_lock();
    let app = test::init_service(build_test_app(RunegateMode::Gateway)).await;
    let email = "gateway-user@example.com";
    let token = create_token(email, get_magic_link_expiry(), "jti-gw").unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/auth?token={}", token))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/proxy/");
    let cookie = extract_session_cookie(&resp).expect("session cookie must be set");

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/debug/session")
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["email"], email);
}
