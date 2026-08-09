// SPDX-License-Identifier: Apache-2.0
//! Application wiring shared by the `runegate` binary and the integration
//! tests: route table, UI handlers, and renderer construction. Keeping this in
//! the library lets tests exercise the real routing table in-process with
//! `actix_web::test::init_service`.

use actix_files::Files;
use actix_session::Session;
use actix_web::http::header;
use actix_web::{Error, HttpRequest, HttpResponse, Responder, web};
use std::sync::Arc;
use tracing::{debug, error, instrument};

use crate::config::{AuthUiMode, RunegateMode, default_redirect};
use crate::proxy::proxy_request;
use crate::rate_limit::RateLimiters;
use crate::ui::context::{
    AuthContext, AuthUiContext, BrandingContext, LocaleContext, MarketContext, MessageContext,
    NavigationContext, RequestContext, SecurityContext,
};

/// Per-process settings that route handlers need at request time. Registered
/// as `web::Data<AppSettings>` and consulted by the proxy fallback handler.
#[derive(Debug, Clone, Copy)]
pub struct AppSettings {
    pub mode: RunegateMode,
    pub debug_endpoints_enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            mode: RunegateMode::MagicLinkOnly,
            debug_endpoints_enabled: false,
        }
    }
}

/// Resolve the directory holding the static auth UI assets (login.html etc.).
///
/// Order: `RUNEGATE_LOGIN_ASSETS_DIR` if set; otherwise the CWD-relative
/// `static/` directory that the published release served from; otherwise the
/// deployed default `/opt/runegate/static`.
pub fn resolve_login_assets_dir() -> String {
    if let Ok(dir) = std::env::var("RUNEGATE_LOGIN_ASSETS_DIR") {
        return dir;
    }
    if std::path::Path::new("static/login.html").exists() {
        return "static".to_string();
    }
    "/opt/runegate/static".to_string()
}

/// Construct the auth UI renderer for the given UI mode.
pub fn build_renderer(auth_ui_mode: AuthUiMode) -> Arc<dyn crate::ui::AuthUiRenderer> {
    match auth_ui_mode {
        AuthUiMode::Phenotyper => {
            let template_dir = std::env::var("RUNEGATE_TEMPLATE_DIR")
                .unwrap_or_else(|_| "/opt/runegate/templates".to_string());
            Arc::new(crate::ui::phenotyper_renderer::PhenotyperRenderer::new(
                std::path::PathBuf::from(template_dir),
            ))
        }
        AuthUiMode::Static | AuthUiMode::External => {
            let assets_dir = resolve_login_assets_dir();
            Arc::new(crate::ui::static_renderer::StaticRenderer::new(
                std::path::PathBuf::from(assets_dir),
            ))
        }
    }
}

#[derive(serde::Deserialize)]
struct AuthQueryParams {
    return_to: Option<String>,
    locale: Option<String>,
}

fn create_auth_ui_context(req: &HttpRequest, query: &AuthQueryParams) -> AuthUiContext {
    let host = req.connection_info().host().to_string();
    let path = req.path().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();

    let return_to = query.return_to.clone().unwrap_or_else(default_redirect);
    let locale_str = query.locale.clone().unwrap_or_else(|| "en".to_string());

    AuthUiContext {
        request: RequestContext {
            host,
            path,
            request_id,
        },
        market: MarketContext {
            id: "global".to_string(),
            canonical_domain: "verbatime.ai".to_string(),
            market_name: "Global".to_string(),
            currency: "EUR".to_string(),
        },
        locale: LocaleContext {
            current: locale_str,
            available: vec![
                "en".to_string(),
                "nl".to_string(),
                "nl-BE".to_string(),
                "de".to_string(),
                "fr".to_string(),
            ],
            default: "en".to_string(),
        },
        branding: BrandingContext {
            product_name: "Verbatime".to_string(),
            logo_url: "/img/logo.svg".to_string(),
            primary_color: "#0ea5e9".to_string(),
            support_email: "support@verbatime.dev".to_string(),
        },
        auth: AuthContext {
            mode: "gateway".to_string(),
            signup_policy: "open".to_string(),
            magic_link_enabled: true,
            google_enabled: true,
            webauthn_enabled: true,
            totp_enabled: true,
        },
        navigation: NavigationContext {
            return_to,
            login_url: "/auth/login".to_string(),
            register_url: "/auth/register".to_string(),
        },
        security: SecurityContext {
            csrf_token: "".to_string(),
            csp_nonce: "".to_string(),
        },
        messages: MessageContext {
            title: "".to_string(),
            subtitle: None,
            flash: None,
            error: None,
        },
    }
}

async fn serve_login(
    req: HttpRequest,
    query: web::Query<AuthQueryParams>,
    renderer: web::Data<dyn crate::ui::AuthUiRenderer>,
    session: Session,
) -> impl Responder {
    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    if is_authenticated {
        let return_to = query.return_to.clone().unwrap_or_else(default_redirect);
        return HttpResponse::Found()
            .append_header((header::LOCATION, return_to))
            .finish();
    }

    let ctx = create_auth_ui_context(&req, &query);
    match renderer.render_login(&ctx) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to render login UI: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to render login UI: {}", e))
        }
    }
}

async fn serve_register(
    req: HttpRequest,
    query: web::Query<AuthQueryParams>,
    renderer: web::Data<dyn crate::ui::AuthUiRenderer>,
    session: Session,
) -> impl Responder {
    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    if is_authenticated {
        let return_to = query.return_to.clone().unwrap_or_else(default_redirect);
        return HttpResponse::Found()
            .append_header((header::LOCATION, return_to))
            .finish();
    }

    let ctx = create_auth_ui_context(&req, &query);
    match renderer.render_register(&ctx) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to render register UI: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to render register UI: {}", e))
        }
    }
}

async fn serve_mfa_select(
    req: HttpRequest,
    query: web::Query<AuthQueryParams>,
    renderer: web::Data<dyn crate::ui::AuthUiRenderer>,
) -> impl Responder {
    let ctx = create_auth_ui_context(&req, &query);
    match renderer.render_mfa_select(&ctx) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to render MFA select UI: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to render MFA select: {}", e))
        }
    }
}

/// Health check endpoint
#[instrument(name = "health_check", skip_all)]
async fn health_check() -> impl Responder {
    let version = env!("CARGO_PKG_VERSION");
    HttpResponse::Ok().json(serde_json::json!({
        "status": "running",
        "service": "Runegate",
        "version": version
    }))
}

/// Authentication check and proxy handler
#[instrument(name = "auth_check_and_proxy", skip(payload, session, settings), fields(path = %req.path(), method = %req.method()))]
async fn auth_check_and_proxy(
    req: HttpRequest,
    payload: web::Payload,
    session: Session,
    settings: web::Data<AppSettings>,
) -> Result<HttpResponse, Error> {
    debug!(
        "[PROXY_AUTH - EVENT] Checking session for proxy request to: {}",
        req.path()
    );

    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    debug!(
        "[PROXY_AUTH - EVENT] Final authenticated value: {}",
        is_authenticated
    );

    let path = req.path();
    // Public proxy paths (landing page and its assets) exist only in gateway
    // mode; magic-link-only mode keeps the published behaviour of gating
    // everything behind authentication.
    let is_public_path = settings.mode == RunegateMode::Gateway
        && (path == "/"
            || path == "/favicon.ico"
            || path == "/favicon.svg"
            || path.starts_with("/_app"));

    if is_authenticated || is_public_path {
        // User is authenticated, or this is a public proxy path (e.g. landing page or assets).
        // Proxy the request. If authenticated, inject identity headers.
        let identity_email = if is_authenticated {
            session.get::<String>("email").ok().flatten()
        } else {
            None
        };
        proxy_request(req, payload, identity_email).await
    } else {
        // User is not authenticated, redirect to login
        // Detect if we're behind a proxy and construct the correct redirect path
        let redirect_path = if req.headers().contains_key("X-Forwarded-Proto") {
            // We're behind a proxy, need to determine the base path
            let original_uri = req.uri().path();
            if original_uri == "/" {
                // We're at the root of the proxied path, redirect to login.html at the same level
                "./login.html".to_string()
            } else {
                // Extract the base path from the original URI
                let path_segments: Vec<&str> =
                    original_uri.trim_start_matches('/').split('/').collect();
                if path_segments.len() > 1 {
                    format!("/{}/login.html", path_segments[0])
                } else {
                    "/login.html".to_string()
                }
            }
        } else {
            // Direct access, use absolute path
            "/login.html".to_string()
        };

        debug!("Redirecting unauthenticated user to: {}", redirect_path);
        Ok(HttpResponse::Found()
            .append_header((header::LOCATION, redirect_path))
            .finish())
    }
}

/// Diagnostic endpoint to return the current rate limiting configuration
#[instrument(name = "rate_limit_info")]
async fn rate_limit_info(rate_limiters: web::Data<Arc<RateLimiters>>) -> impl Responder {
    let rate_limit_config = rate_limiters.config.clone();
    HttpResponse::Ok().json(rate_limit_config)
}

/// Debug endpoint to inspect server-side session view
#[instrument(name = "debug_session", skip(session, req))]
async fn debug_session(req: HttpRequest, session: Session) -> impl Responder {
    let session_status = format!("{:?}", session.status());
    let entries = session.entries();
    let entry_keys: Vec<String> = entries.keys().cloned().collect();
    let authenticated = session.get::<bool>("authenticated").ok().flatten();
    let email = session.get::<String>("email").ok().flatten();
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    let pid = std::process::id();

    HttpResponse::Ok().json(serde_json::json!({
        "session_status": session_status,
        "entry_keys": entry_keys,
        "authenticated": authenticated,
        "email": email,
        "cookie_header": cookie_header,
        "client_ip": client_ip,
        "pid": pid,
    }))
}

/// Debug endpoint to inspect parsed cookies
#[instrument(name = "debug_cookies", skip(req))]
async fn debug_cookies(req: HttpRequest) -> impl Responder {
    let raw_cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let parsed = match req.cookies() {
        Ok(cs) => Some(
            cs.iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name(),
                        "value": c.value(),
                        "path": c.path().map(|s| s.to_string()),
                        "domain": c.domain().map(|s| s.to_string()),
                        "http_only": c.http_only().unwrap_or(false),
                        "secure": c.secure().unwrap_or(false),
                        "same_site": c.same_site().map(|s| format!("{:?}", s)),
                    })
                })
                .collect::<Vec<_>>(),
        ),
        Err(_e) => None,
    };
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    HttpResponse::Ok().json(serde_json::json!({
        "raw_cookie_header": raw_cookie_header,
        "parsed": parsed,
        "client_ip": client_ip,
    }))
}

/// Debug endpoint that goes through auth middleware to verify auth gating
#[instrument(name = "debug_protected", skip(session))]
async fn debug_protected(session: Session) -> impl Responder {
    let authenticated = session
        .get::<bool>("authenticated")
        .ok()
        .flatten()
        .unwrap_or(false);
    let email = session.get::<String>("email").ok().flatten();
    HttpResponse::Ok().json(serde_json::json!({
        "authenticated": authenticated,
        "email": email,
        "note": "This endpoint requires auth via middleware. Redirects to /login.html if not authed.",
    }))
}

/// Register the full Runegate route table. This is the single source of truth
/// for routing, used by the binary and by integration tests.
///
/// App data (`AppConfig`, `RateLimiters`, the renderer, optional `PgStore`,
/// and `AppSettings`) and the session/auth middleware are registered by the
/// caller.
pub fn configure_routes(cfg: &mut web::ServiceConfig, settings: &AppSettings) {
    cfg
        // API Endpoints - define these first to ensure they take priority
        .service(web::resource("/health").route(web::get().to(health_check)))
        .service(
            web::resource("/auth/identify").route(web::post().to(crate::routes::auth::identify)),
        )
        .service(
            web::resource("/auth/magic/start")
                .route(web::post().to(crate::routes::auth::magic_start)),
        )
        .service(
            web::resource("/auth/magic/consume")
                .route(web::get().to(crate::routes::auth::magic_consume)),
        )
        // Aliases for backward compatibility
        .service(web::resource("/login").route(web::post().to(crate::routes::auth::magic_start)))
        .service(web::resource("/auth").route(web::get().to(crate::routes::auth::magic_consume)))
        // OIDC Endpoints
        .service(
            web::resource("/auth/google/start")
                .route(web::get().to(crate::routes::oidc::google_start)),
        )
        .service(
            web::resource("/auth/google/callback")
                .route(web::get().to(crate::routes::oidc::google_callback)),
        )
        // MFA Endpoints
        .service(
            web::resource("/mfa/totp/verify")
                .route(web::post().to(crate::routes::mfa::totp_verify)),
        )
        .service(
            web::resource("/mfa/webauthn/start")
                .route(web::post().to(crate::routes::mfa::webauthn_start)),
        )
        .service(
            web::resource("/mfa/webauthn/finish")
                .route(web::post().to(crate::routes::mfa::webauthn_finish)),
        )
        // Upload Endpoints
        .service(
            web::resource("/upload-ticket")
                .route(web::post().to(crate::routes::upload::create_upload_ticket)),
        )
        .service(
            web::resource("/keys/upload_jwks.json")
                .route(web::get().to(crate::routes::upload::get_upload_jwks)),
        )
        // Admin Endpoints
        .service(
            web::resource("/admin/invites")
                .route(web::post().to(crate::routes::admin::create_invite))
                .route(web::get().to(crate::routes::admin::get_invites)),
        )
        .service(
            web::resource("/admin/invites/{id}/revoke")
                .route(web::post().to(crate::routes::admin::revoke_invite)),
        )
        .service(web::resource("/rate_limit_info").route(web::get().to(rate_limit_info)))
        // UI Endpoints
        .service(web::resource("/auth/login").route(web::get().to(serve_login)))
        .service(web::resource("/auth/login.html").route(web::get().to(serve_login)))
        .service(web::resource("/login.html").route(web::get().to(serve_login)))
        .service(web::resource("/auth/register").route(web::get().to(serve_register)))
        .service(web::resource("/auth/register.html").route(web::get().to(serve_register)))
        .service(web::resource("/register.html").route(web::get().to(serve_register)))
        .service(web::resource("/mfa").route(web::get().to(serve_mfa_select)));

    if settings.debug_endpoints_enabled {
        cfg.service(web::resource("/debug/session").route(web::get().to(debug_session)))
            .service(web::resource("/debug/cookies").route(web::get().to(debug_cookies)))
            .service(web::resource("/debug/protected").route(web::get().to(debug_protected)));
    }

    cfg
        // Static files serving - place after API endpoints to avoid routing conflicts
        .service(Files::new("/auth", "static"))
        .service(Files::new("/static", "static"))
        .service(Files::new("/img", "static/img"))
        // Protected routes need to be guarded in each handler
        .default_service(web::route().to(auth_check_and_proxy));
}
