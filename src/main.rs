// SPDX-License-Identifier: Apache-2.0
use actix_files::Files;
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::{Key, SameSite};
use actix_web::http::header;
use actix_web::middleware::Condition;
use actix_web::{App, Error, HttpRequest, HttpResponse, HttpServer, Responder, web};

use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use runegate::logging;
use rand::RngExt;
use runegate::email::EmailConfig;
use runegate::memory_session_store::MemorySessionStore;
use runegate::middleware::AuthMiddleware;
use runegate::proxy::proxy_request;
use runegate::rate_limit::RateLimiters;
use runegate::store::pg::PgStore;
use tracing_actix_web::TracingLogger; // Added for random key generation
use runegate::ui::context::{
    AuthUiContext, RequestContext, MarketContext, LocaleContext,
    BrandingContext, AuthContext, NavigationContext, SecurityContext, MessageContext
};

// Application configuration constants
const SESSION_KEY_ENV: &str = "RUNEGATE_SESSION_KEY";
const RUNEGATE_ENV: &str = "RUNEGATE_ENV"; // Environment variable to check for production mode
const RUNEGATE_SECURE_COOKIE_VAR: &str = "RUNEGATE_SECURE_COOKIE";
const RUNEGATE_COOKIE_DOMAIN_VAR: &str = "RUNEGATE_COOKIE_DOMAIN";
const RUNEGATE_SESSION_COOKIE_NAME_VAR: &str = "RUNEGATE_SESSION_COOKIE_NAME";
const RUNEGATE_DEBUG_ENDPOINTS_VAR: &str = "RUNEGATE_DEBUG_ENDPOINTS";
const RUNEGATE_MODE_VAR: &str = "RUNEGATE_MODE";
const RUNEGATE_AUTH_UI_MODE_VAR: &str = "RUNEGATE_AUTH_UI_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunegateMode {
    #[default]
    MagicLinkOnly,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthUiMode {
    #[default]
    Static,
    Phenotyper,
    External,
}

// We'll get the magic link expiry from environment instead of hardcoding it
// Default is defined in auth.rs as DEFAULT_MAGIC_LINK_EXPIRY

use runegate::config::AppConfig;

#[derive(serde::Deserialize)]
struct AuthQueryParams {
    return_to: Option<String>,
    locale: Option<String>,
}

fn create_auth_ui_context(req: &HttpRequest, query: &AuthQueryParams) -> AuthUiContext {
    let host = req.connection_info().host().to_string();
    let path = req.path().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();

    let return_to = query.return_to.clone().unwrap_or_else(|| "/app".to_string());
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
            available: vec!["en".to_string(), "nl".to_string(), "nl-BE".to_string(), "de".to_string(), "fr".to_string()],
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
    renderer: web::Data<dyn runegate::ui::AuthUiRenderer>,
    session: Session,
) -> impl Responder {
    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    if is_authenticated {
        let return_to = query.return_to.clone().unwrap_or_else(|| "/app".to_string());
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
    renderer: web::Data<dyn runegate::ui::AuthUiRenderer>,
    session: Session,
) -> impl Responder {
    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    if is_authenticated {
        let return_to = query.return_to.clone().unwrap_or_else(|| "/app".to_string());
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
    renderer: web::Data<dyn runegate::ui::AuthUiRenderer>,
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
#[instrument(name = "auth_check_and_proxy", skip(payload, session), fields(path = %req.path(), method = %req.method()))]
async fn auth_check_and_proxy(
    req: HttpRequest,
    payload: web::Payload,
    session: Session,
) -> Result<HttpResponse, Error> {
    // Check if user is authenticated
    debug!(
        "[PROXY_AUTH - EVENT] Checking session for proxy request to: {}",
        req.path()
    );

    match session.get::<bool>("authenticated") {
        Ok(Some(val)) => debug!(
            "[PROXY_AUTH - EVENT] Session authenticated result: Ok(Some({}))",
            val
        ),
        Ok(None) => debug!("[PROXY_AUTH - EVENT] Session authenticated result: Ok(None)"),
        Err(e) => debug!("[PROXY_AUTH - EVENT] Session authenticated error: {}", e),
    }

    match session.get::<String>("email") {
        Ok(Some(val)) => debug!(
            "[PROXY_AUTH - EVENT] Session email result: Ok(Some({}))",
            val
        ),
        Ok(None) => debug!("[PROXY_AUTH - EVENT] Session email result: Ok(None)"),
        Err(e) => debug!("[PROXY_AUTH - EVENT] Session email error: {}", e),
    }

    let is_authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(None)
        .unwrap_or(false);
    debug!(
        "[PROXY_AUTH - EVENT] Final authenticated value: {}",
        is_authenticated
    );

    let path = req.path();
    let is_public_path = path == "/"
        || path == "/favicon.ico"
        || path == "/favicon.svg"
        || path.starts_with("/_app");

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

/// Load configuration from TOML file
fn load_config() -> AppConfig {
    // Try multiple locations for the email config file
    // 1. First try the system-installed location (for deployed environments)
    // 2. Then try the local development path
    let config_paths = [
        "/etc/runegate/config/email.toml", // System-installed path
        "config/email.toml",               // Development path
    ];

    // Try each path until one works
    let mut config_text = None;
    let mut last_error = None;

    for path in &config_paths {
        match fs::read_to_string(path) {
            Ok(content) => {
                info!("Loaded email configuration from {}", path);
                config_text = Some(content);
                break;
            }
            Err(err) => {
                debug!("Could not load email config from {}: {}", path, err);
                last_error = Some(err);
            }
        }
    }

    // Unwrap the configuration or fail with the last error
    let config_text = config_text.unwrap_or_else(|| {
        error!("Failed to load email configuration from any of the specified paths");
        panic!(
            "Failed to read email config file: {:?}",
            last_error.unwrap()
        );
    });

    // Parse the email configuration
    let email_config: EmailConfig =
        toml::from_str(&config_text).expect("Failed to parse email config");

    // Get base URL from environment or use default
    let base_url =
        std::env::var("RUNEGATE_BASE_URL").unwrap_or_else(|_| "http://localhost:7870".to_string());

    let upload_private_key = std::env::var("RUNEGATE_UPLOAD_PRIVATE_KEY").ok();
    let upload_jwks = std::env::var("RUNEGATE_UPLOAD_JWKS").ok();

    AppConfig {
        base_url,
        email_config,
        google_oidc: None, // Load from env or file later if needed
        upload_private_key,
        upload_jwks,
    }
}

/// Get session key from environment or use default
fn get_session_key() -> Key {
    match std::env::var(SESSION_KEY_ENV) {
        Ok(key_str) => {
            let key_str = key_str.trim(); // Remove any whitespace/newlines
            info!(
                "Session key debug: length={}, is_hex={}",
                key_str.len(),
                key_str.chars().all(|c| c.is_ascii_hexdigit())
            );

            // Try to decode as hex first (128 hex chars = 64 bytes)
            if key_str.len() == 128 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
                info!("Attempting hex decode of session key");
                match hex::decode(key_str) {
                    Ok(key_bytes) => {
                        if key_bytes.len() == 64 {
                            info!("Successfully decoded hex session key to 64 bytes");
                            return Key::from(&key_bytes);
                        } else {
                            warn!(
                                "Hex decoded session key is {} bytes, not 64",
                                key_bytes.len()
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to decode hex RUNEGATE_SESSION_KEY: {}", e);
                    }
                }
            } else {
                info!("Session key not 128 hex chars, using as raw bytes");
            }

            // Fall back to treating as raw bytes
            let key_bytes = key_str.as_bytes();
            if key_bytes.len() < 64 {
                error!(
                    "RUNEGATE_SESSION_KEY is set but is less than 64 bytes ({} bytes). This is insecure.",
                    key_bytes.len()
                );
                panic!("RUNEGATE_SESSION_KEY must be at least 64 bytes.");
            }
            info!("Using session key as raw bytes: {} bytes", key_bytes.len());
            Key::from(key_bytes)
        }
        Err(_) => match std::env::var(RUNEGATE_ENV).as_deref() {
            Ok("production") => {
                error!("CRITICAL: RUNEGATE_SESSION_KEY is not set in a production environment!");
                panic!("RUNEGATE_SESSION_KEY must be set in production.");
            }
            _ => {
                warn!(
                    "RUNEGATE_SESSION_KEY is not set. Generating a temporary random key. \
                        This is NOT suitable for production. Please set RUNEGATE_SESSION_KEY (min 64 bytes)."
                );
                let mut rng = rand::rng();
                let mut key = [0u8; 64];
                rng.fill(&mut key);
                Key::from(&key)
            }
        },
    }
}

/// Log environment configuration with sensitive values redacted
fn log_environment_config() {
    // Environment mode
    let env_mode = std::env::var("RUNEGATE_ENV").unwrap_or_else(|_| "development".to_string());
    info!("🔧 Environment mode: {}", env_mode);

    // Runegate mode (magic-link-only or gateway)
    let runegate_mode =
        std::env::var(RUNEGATE_MODE_VAR).unwrap_or_else(|_| "magic-link-only".to_string());
    info!("🔄 Runegate mode: {}", runegate_mode);

    // Auth UI mode (static, phenotyper, external)
    let ui_mode = std::env::var(RUNEGATE_AUTH_UI_MODE_VAR).unwrap_or_else(|_| "static".to_string());
    info!("🎨 Auth UI mode: {}", ui_mode);

    // JWT Secret (length only for security)
    match std::env::var("RUNEGATE_JWT_SECRET") {
        Ok(secret) => info!("🔐 JWT secret: configured ({} bytes)", secret.len()),
        Err(_) => warn!("⚠️  JWT secret: not set, using development default"),
    }

    // Session Key (length only for security)
    match std::env::var("RUNEGATE_SESSION_KEY") {
        Ok(key) => info!("🍪 Session key: configured ({} bytes)", key.len()),
        Err(_) => warn!("⚠️  Session key: not set, using development default"),
    }

    // Target service
    let target_service = std::env::var("RUNEGATE_TARGET_SERVICE")
        .unwrap_or_else(|_| "http://127.0.0.1:7860".to_string());
    info!("🎯 Target service: {}", target_service);

    // Base URL
    let base_url =
        std::env::var("RUNEGATE_BASE_URL").unwrap_or_else(|_| "http://localhost:7870".to_string());
    info!("🌐 Base URL: {}", base_url);

    // Magic link expiry
    let expiry = std::env::var("RUNEGATE_MAGIC_LINK_EXPIRY").unwrap_or_else(|_| "15".to_string());
    info!("⏰ Magic link expiry: {} minutes", expiry);

    // Secure cookies
    let secure_cookie =
        std::env::var("RUNEGATE_SECURE_COOKIE").unwrap_or_else(|_| "auto".to_string());
    info!("🔒 Secure cookies: {}", secure_cookie);

    // Cookie domain (optional)
    match std::env::var(RUNEGATE_COOKIE_DOMAIN_VAR) {
        Ok(domain) if !domain.trim().is_empty() => info!("🍪 Cookie domain: {}", domain.trim()),
        _ => info!("🍪 Cookie domain: (unset - host-only)"),
    }

    // Rate limiting
    let rate_limit_enabled =
        std::env::var("RUNEGATE_RATE_LIMIT_ENABLED").unwrap_or_else(|_| "true".to_string());
    info!("🛡️  Rate limiting: {}", rate_limit_enabled);

    if rate_limit_enabled == "true" {
        let login_limit =
            std::env::var("RUNEGATE_LOGIN_RATE_LIMIT").unwrap_or_else(|_| "5".to_string());
        let email_cooldown =
            std::env::var("RUNEGATE_EMAIL_COOLDOWN").unwrap_or_else(|_| "300".to_string());
        let token_limit =
            std::env::var("RUNEGATE_TOKEN_RATE_LIMIT").unwrap_or_else(|_| "10".to_string());
        info!(
            "   📊 Login limit: {}/min/IP, Email cooldown: {}s, Token limit: {}/min/IP",
            login_limit, email_cooldown, token_limit
        );
    }

    // Logging configuration
    let log_format = std::env::var("RUNEGATE_LOG_FORMAT").unwrap_or_else(|_| "console".to_string());
    info!("📝 Log format: {}", log_format);
    // Session cookie name
    let cookie_name = std::env::var(RUNEGATE_SESSION_COOKIE_NAME_VAR)
        .unwrap_or_else(|_| "runegate_id".to_string());
    info!("🍪 Session cookie name: {}", cookie_name);
    // Debug endpoints flag
    let debug_flag =
        std::env::var(RUNEGATE_DEBUG_ENDPOINTS_VAR).unwrap_or_else(|_| "auto".to_string());
    info!(
        "🧪 Debug endpoints flag: {} (auto=false in production)",
        debug_flag
    );
}

/// Load environment file from multiple possible locations
fn load_env_file() {
    // Try multiple locations for the environment file
    // 1. First try the system-installed location (for deployed environments)
    // 2. Then try the local development path
    let env_paths = [
        "/etc/runegate/runegate.env", // System-installed path
        ".env",                       // Development path
    ];

    // Try each path until one works
    for path in &env_paths {
        match dotenvy::from_path(path) {
            Ok(_) => {
                info!("Loaded environment configuration from {}", path);
                return;
            }
            Err(err) => {
                debug!("Could not load environment config from {}: {}", path, err);
            }
        }
    }

    // If no .env file found, that's okay - environment variables can still be set directly
    debug!(
        "No .env file found in any of the expected locations, using system environment variables only"
    );
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env file from multiple possible locations
    load_env_file();

    // Configure logging based on RUNEGATE_LOG_FORMAT environment variable
    // This can be set in .env file or directly in the environment
    // Default is "console", alternatives are "json"
    let log_format = std::env::var("RUNEGATE_LOG_FORMAT").unwrap_or_else(|_| "console".to_string());

    // Initialize logging based on the format setting
    if log_format == "json" {
        logging::init_tracing("runegate", std::io::stdout);
        // Now we can log after initialization
        info!("Using JSON structured logging");
    } else {
        logging::init_console_tracing();
        // Now we can log after initialization
        info!("Using console logging for development");
    }

    // Initialize rate limiters
    let rate_limiters = Arc::new(RateLimiters::new());

    // Log configuration information
    let version = env!("CARGO_PKG_VERSION");
    info!("🚪 Starting Runegate auth proxy v{}", version);

    // Parse RUNEGATE_MODE
    let runegate_mode = match std::env::var(RUNEGATE_MODE_VAR).as_deref() {
        Ok("gateway") => RunegateMode::Gateway,
        _ => RunegateMode::MagicLinkOnly,
    };
    info!("🚀 Operating in {:?} mode", runegate_mode);

    // Parse RUNEGATE_AUTH_UI_MODE
    let auth_ui_mode = match std::env::var(RUNEGATE_AUTH_UI_MODE_VAR).as_deref() {
        Ok("phenotyper") => AuthUiMode::Phenotyper,
        Ok("external") => AuthUiMode::External,
        _ => AuthUiMode::Static,
    };
    info!("🎨 Auth UI configured for {:?} mode", auth_ui_mode);

    // Initialize Auth UI Renderer
    let renderer: std::sync::Arc<dyn runegate::ui::AuthUiRenderer> = match auth_ui_mode {
        AuthUiMode::Phenotyper => {
            let template_dir = std::env::var("RUNEGATE_TEMPLATE_DIR")
                .unwrap_or_else(|_| "/opt/runegate/templates".to_string());
            std::sync::Arc::new(runegate::ui::phenotyper_renderer::PhenotyperRenderer::new(
                std::path::PathBuf::from(template_dir),
            ))
        }
        AuthUiMode::Static | AuthUiMode::External => {
            let assets_dir = std::env::var("RUNEGATE_LOGIN_ASSETS_DIR")
                .unwrap_or_else(|_| "/opt/runegate/static".to_string());
            std::sync::Arc::new(runegate::ui::static_renderer::StaticRenderer::new(
                std::path::PathBuf::from(assets_dir),
            ))
        }
    };
    let renderer_data = web::Data::from(renderer);

    // Log environment configuration (redacting sensitive values)
    log_environment_config();

    // Load application configuration
    let config = load_config();
    let app_config = web::Data::new(config);

    // Initialize PostgreSQL store if configured
    let pg_store = PgStore::new().await.unwrap_or_else(|e| {
        error!("Failed to initialize PostgreSQL store: {}", e);
        None
    });

    // Set up the session key for cookies
    let session_key = get_session_key();
    // Create a shared session store based on configuration
    let shared_session_store = match std::env::var("REDIS_URL") {
        Ok(redis_url) => {
            info!("🔌 Initializing Redis Session Store...");
            match actix_session::storage::RedisSessionStore::new(redis_url).await {
                Ok(redis_store) => {
                    info!("✅ Redis Session Store initialized successfully");
                    runegate::store::session::RunegateSessionStore::Redis(redis_store)
                }
                Err(e) => {
                    error!("❌ Failed to connect to Redis: {}", e);
                    panic!("Redis connection failed, but REDIS_URL was provided.");
                }
            }
        }
        Err(_) => {
            info!("🧠 Initializing In-Memory Session Store...");
            runegate::store::session::RunegateSessionStore::Memory(MemorySessionStore::new())
        }
    };

    // Create shared data for rate limiters
    let rate_limiters_data = web::Data::new(rate_limiters.clone());
    // Determine session cookie name
    let session_cookie_name = std::env::var(RUNEGATE_SESSION_COOKIE_NAME_VAR)
        .unwrap_or_else(|_| "runegate_id".to_string());
    // Determine if debug endpoints should be enabled
    let debug_endpoints_enabled = match std::env::var(RUNEGATE_DEBUG_ENDPOINTS_VAR) {
        Ok(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => true,
        Ok(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => false,
        _ => std::env::var(RUNEGATE_ENV).as_deref() != Ok("production"),
    };
    if debug_endpoints_enabled {
        info!("🧪 Debug endpoints ENABLED");
    } else {
        info!("🧪 Debug endpoints DISABLED");
    }

    // Determine worker count from environment (default to 2)
    let workers_env = std::env::var("RUNEGATE_WORKERS").ok();
    let workers = workers_env
        .as_deref()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2);
    info!("🧵 Workers: {}", workers);

    // Control request access logging via env (off by default in production)
    let request_logs_enabled = match std::env::var("RUNEGATE_REQUEST_LOGS") {
        Ok(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => true,
        Ok(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => false,
        _ => std::env::var(RUNEGATE_ENV).as_deref() != Ok("production"),
    };

    HttpServer::new(move || {
        let pg_store_instance = pg_store.clone();
        
        // Determine cookie_secure setting
        let secure_cookie = match std::env::var(RUNEGATE_SECURE_COOKIE_VAR).as_deref() {
            Ok("true") => {
                info!("Using secure cookies as {} is set to 'true'.", RUNEGATE_SECURE_COOKIE_VAR);
                true
            }
            Ok("false") => {
                info!("Using insecure cookies as {} is set to 'false'.", RUNEGATE_SECURE_COOKIE_VAR);
                false
            }
            _ => { // RUNEGATE_SECURE_COOKIE_VAR is not set or has an invalid value
                match std::env::var(RUNEGATE_ENV).as_deref() {
                    Ok("production") => {
                        info!("Using secure cookies as {} is set to 'production' and {} is not set.", RUNEGATE_ENV, RUNEGATE_SECURE_COOKIE_VAR);
                        true
                    }
                    _ => {
                        warn!(
                            "Using insecure cookies by default. Set {} or {} to 'true' or '{}' to 'production' for secure cookies.",
                            RUNEGATE_SECURE_COOKIE_VAR, RUNEGATE_ENV, RUNEGATE_ENV
                        );
                        false
                    }
                }
            }
        };

        // Determine cookie domain (optional)
        let cookie_domain_opt = std::env::var(RUNEGATE_COOKIE_DOMAIN_VAR)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match &cookie_domain_opt {
            Some(d) => info!("Using cookie domain: {}", d),
            None => info!("No cookie domain set; using host-only cookies"),
        }

        {
            let mut app = App::new()
                // Access logging (gate by env; default off in production)
                .wrap(Condition::new(request_logs_enabled, TracingLogger::default()))
                // Ensure SessionMiddleware runs before AuthMiddleware so session is available in auth checks
                .wrap(AuthMiddleware::new())
                .wrap(
                    SessionMiddleware::builder(shared_session_store.clone(), session_key.clone())
                        .cookie_secure(secure_cookie)
                        .cookie_http_only(true)
                        .cookie_same_site(SameSite::Lax)
                        .cookie_path("/".to_string())
                        .cookie_domain(cookie_domain_opt)
                        .cookie_name(session_cookie_name.clone())
                        .build()
                )
                // App data
                .app_data(app_config.clone())
                .app_data(rate_limiters_data.clone())
                .app_data(renderer_data.clone());
                
            if let Some(pg) = &pg_store_instance {
                app = app.app_data(web::Data::new(pg.clone()));
            }

            let mut app = app
                // API Endpoints - define these first to ensure they take priority
                .service(web::resource("/health").route(web::get().to(health_check)))
                .service(web::resource("/auth/identify").route(web::post().to(runegate::routes::auth::identify)))
                .service(web::resource("/auth/magic/start").route(web::post().to(runegate::routes::auth::magic_start)))
                .service(web::resource("/auth/magic/consume").route(web::get().to(runegate::routes::auth::magic_consume)))
                // Aliases for backward compatibility
                .service(web::resource("/login").route(web::post().to(runegate::routes::auth::magic_start)))
                .service(web::resource("/auth").route(web::get().to(runegate::routes::auth::magic_consume)))
                // OIDC Endpoints
                .service(web::resource("/auth/google/start").route(web::get().to(runegate::routes::oidc::google_start)))
                .service(web::resource("/auth/google/callback").route(web::get().to(runegate::routes::oidc::google_callback)))
                // MFA Endpoints
                .service(web::resource("/mfa/totp/verify").route(web::post().to(runegate::routes::mfa::totp_verify)))
                .service(web::resource("/mfa/webauthn/start").route(web::post().to(runegate::routes::mfa::webauthn_start)))
                .service(web::resource("/mfa/webauthn/finish").route(web::post().to(runegate::routes::mfa::webauthn_finish)))
                // Upload Endpoints
                .service(web::resource("/upload-ticket").route(web::post().to(runegate::routes::upload::create_upload_ticket)))
                .service(web::resource("/keys/upload_jwks.json").route(web::get().to(runegate::routes::upload::get_upload_jwks)))
                // Admin Endpoints
                .service(web::resource("/admin/invites").route(web::post().to(runegate::routes::admin::create_invite)).route(web::get().to(runegate::routes::admin::get_invites)))
                .service(web::resource("/admin/invites/{id}/revoke").route(web::post().to(runegate::routes::admin::revoke_invite)))
                .service(web::resource("/rate_limit_info").route(web::get().to(rate_limit_info)))
                // UI Endpoints
                .service(web::resource("/auth/login").route(web::get().to(serve_login)))
                .service(web::resource("/auth/login.html").route(web::get().to(serve_login)))
                .service(web::resource("/login.html").route(web::get().to(serve_login)))
                .service(web::resource("/auth/register").route(web::get().to(serve_register)))
                .service(web::resource("/auth/register.html").route(web::get().to(serve_register)))
                .service(web::resource("/register.html").route(web::get().to(serve_register)))
                .service(web::resource("/mfa").route(web::get().to(serve_mfa_select)));

            if debug_endpoints_enabled {
                app = app
                    .service(web::resource("/debug/session").route(web::get().to(debug_session)))
                    .service(web::resource("/debug/cookies").route(web::get().to(debug_cookies)))
                    .service(web::resource("/debug/protected").route(web::get().to(debug_protected)));
            }

            app
                // Static files serving - place after API endpoints to avoid routing conflicts
                .service(Files::new("/auth", "static"))
                .service(Files::new("/static", "static"))
                .service(Files::new("/img", "static/img"))
                // Protected routes need to be guarded in each handler
                .default_service(web::route().to(auth_check_and_proxy))
        }
    })
    .bind("0.0.0.0:7870")?
    .client_request_timeout(Duration::from_secs(600))
    .keep_alive(Duration::from_secs(15))
    .backlog(2048)
    .workers(workers)
    .run()
    .await
}
