// SPDX-License-Identifier: Apache-2.0
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, Error};
use tracing::{info, warn, error, debug, instrument};
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::{Key, SameSite};
use actix_web::http::header;
use actix_files::Files;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::fs;
use std::sync::Arc;

use runegate::email::EmailConfig;
use runegate::send_magic_link::send_magic_link;
use runegate::memory_session_store::MemorySessionStore;
use runegate::auth::{generate_magic_link, verify_token, get_magic_link_expiry};
use runegate::proxy::proxy_request;
use runegate::logging;
use runegate::middleware::AuthMiddleware;
use runegate::rate_limit::RateLimiters;
use tracing_actix_web::TracingLogger;
use rand::Rng; // Added for random key generation

// Application configuration constants
const SESSION_KEY_ENV: &str = "RUNEGATE_SESSION_KEY";
const RUNEGATE_ENV: &str = "RUNEGATE_ENV"; // Environment variable to check for production mode
const RUNEGATE_SECURE_COOKIE_VAR: &str = "RUNEGATE_SECURE_COOKIE";
const RUNEGATE_COOKIE_DOMAIN_VAR: &str = "RUNEGATE_COOKIE_DOMAIN";
const RUNEGATE_SESSION_COOKIE_NAME_VAR: &str = "RUNEGATE_SESSION_COOKIE_NAME";
const RUNEGATE_DEBUG_ENDPOINTS_VAR: &str = "RUNEGATE_DEBUG_ENDPOINTS";

// We'll get the magic link expiry from environment instead of hardcoding it
// Default is defined in auth.rs as DEFAULT_MAGIC_LINK_EXPIRY

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    base_url: String,
    email_config: EmailConfig,
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

/// Login endpoint that sends a magic link via email
#[instrument(name = "login", skip(app_config, rate_limiters), fields(email = %login_data.email))]
async fn login(
    login_data: web::Json<LoginRequest>, 
    app_config: web::Data<AppConfig>,
    rate_limiters: web::Data<Arc<RateLimiters>>,
    req: HttpRequest
) -> impl Responder {
    let email = &login_data.email;
    let base_url = &app_config.base_url;
    
    // Get the client IP address
    let client_ip = req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    
    // Check if IP is rate limited for login attempts
    if !rate_limiters.login_limiter.check_ip(&client_ip) {
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "IP"))
            .append_header(("X-RateLimit-Reset", "60")) // Added header
            .json("Too many login attempts from this IP address. Please try again later.");
    }
    
    // Check if this email is rate-limited (cooldown between magic link requests)
    if let Some(remaining_seconds) = rate_limiters.email_limiter.check_email(email) {
        warn!("Rate limited attempt to send magic link to {}, cooldown: {} seconds", email, remaining_seconds);
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "Email"))
            .append_header(("X-RateLimit-Reset", remaining_seconds.to_string()))
            .json(format!("Please wait {} seconds before requesting another magic link", remaining_seconds));
    }
    
    // Generate a magic link with JWT token using configurable expiry time
    let expiry_minutes = get_magic_link_expiry();
    let login_url = match generate_magic_link(email, base_url, expiry_minutes) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to generate magic link: {}", e);
            // Consider more specific error responses based on AuthError variants if needed
            return HttpResponse::InternalServerError().json("Failed to generate magic link due to internal error.");
        }
    };
    
    // Log the expiry time for debugging
    info!("📧 Magic link generated with {} minutes expiry", expiry_minutes);
    
    // Send the email
    match send_magic_link(&app_config.email_config, email, &login_url, expiry_minutes) {
        Ok(_) => {
            info!("📧 Magic link sent to {}", email);
            HttpResponse::Ok().json(format!("Magic link sent to {}", email))
        },
        Err(e) => {
            warn!("Failed to send magic link: {}", e); // This is for email sending failure
            HttpResponse::InternalServerError().json("Failed to send login email")
        }
    }
}

/// Auth endpoint that verifies a token from the magic link
#[instrument(name = "auth", skip(session, rate_limiters))]
async fn auth(
    req: HttpRequest, 
    session: actix_session::Session,
    rate_limiters: web::Data<Arc<RateLimiters>>
) -> impl Responder {
    // Get the client IP address for rate limiting
    let client_ip = req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    
    // Check if the IP is rate limited for token verification attempts
    if !rate_limiters.token_limiter.check_ip(&client_ip) {
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "IP"))
            .append_header(("X-RateLimit-Reset", "60")) // Added header
            .json("Too many token verification attempts from this IP. Please try again later.");
    }

    // Check for the token query parameter
    let token = match req.query_string().strip_prefix("token=") {
        Some(token) => token,
        None => return HttpResponse::BadRequest().json("No token provided"),
    };

    // Verify the token and extract user info
    match verify_token(token) {
        Ok(email) => {
            // If token is valid, mark the session as authenticated
            info!("[AUTH_FLOW] About to set session data for user: {}", email);
            
            // Check initial session state
            info!("[AUTH_FLOW] Initial session status: {:?}", session.status());
            info!("[AUTH_FLOW] Initial session entries: {:?}", session.entries());
            
            if let Err(e) = session.insert("authenticated", true) {
                error!("Failed to set authenticated session: {}", e);
                return HttpResponse::InternalServerError().json("Session error");
            }
            info!("[AUTH_FLOW] Session insert authenticated=true: OK");
            
            if let Err(e) = session.insert("email", email.clone()) {
                error!("Failed to set email in session: {}", e);
                return HttpResponse::InternalServerError().json("Session error");
            }
            info!("[AUTH_FLOW] Session insert email={}: OK", email);
            
            // Check session after inserts
            info!("[AUTH_FLOW] After inserts session status: {:?}", session.status());
            info!("[AUTH_FLOW] After inserts session entries: {:?}", session.entries());
            
            // Force session save to ensure data persistence
            session.renew();
            info!("[AUTH_FLOW] Session renewed to ensure persistence");
            info!("[AUTH_FLOW] After renew session status: {:?}", session.status());
            
            // Verify session data was stored
            match session.get::<bool>("authenticated") {
                Ok(Some(val)) => info!("[AUTH_FLOW] Session verification: authenticated={}", val),
                Ok(None) => warn!("[AUTH_FLOW] Session verification: authenticated=None (not found)"),
                Err(e) => warn!("[AUTH_FLOW] Session verification error: {}", e),
            }
            
            // Also verify email
            match session.get::<String>("email") {
                Ok(Some(val)) => info!("[AUTH_FLOW] Session verification: email={}", val),
                Ok(None) => warn!("[AUTH_FLOW] Session verification: email=None (not found)"),
                Err(e) => warn!("[AUTH_FLOW] Session verification error for email: {}", e),
            }
            
            info!("✅ User {} authenticated successfully", email);
            
            // Debug: Show cookies being set
            info!("[AUTH_DEBUG] About to redirect to /proxy/ - session should be set");
            
            // Redirect to the protected service after successful auth
            HttpResponse::Found()
                .append_header((header::LOCATION, "/proxy/"))
                .finish()
        },
        Err(err) => {
            warn!("Token validation error: {}", err);
            HttpResponse::Unauthorized().json("Invalid or expired login link")
        }
    }
}


/// Authentication check and proxy handler
#[instrument(name = "auth_check_and_proxy", skip(body, session), fields(path = %req.path(), method = %req.method()))]
async fn auth_check_and_proxy(req: HttpRequest, body: web::Bytes, session: Session) -> Result<HttpResponse, Error> {
    // Check if user is authenticated
    info!("[PROXY_AUTH - EVENT] Checking session for proxy request to: {}", req.path());
    
    match session.get::<bool>("authenticated") {
        Ok(Some(val)) => info!("[PROXY_AUTH - EVENT] Session authenticated result: Ok(Some({}))", val),
        Ok(None) => info!("[PROXY_AUTH - EVENT] Session authenticated result: Ok(None)"),
        Err(e) => info!("[PROXY_AUTH - EVENT] Session authenticated error: {}", e),
    }
    
    match session.get::<String>("email") {
        Ok(Some(val)) => info!("[PROXY_AUTH - EVENT] Session email result: Ok(Some({}))", val),
        Ok(None) => info!("[PROXY_AUTH - EVENT] Session email result: Ok(None)"),
        Err(e) => info!("[PROXY_AUTH - EVENT] Session email error: {}", e),
    }
    
    let is_authenticated = session.get::<bool>("authenticated").unwrap_or(None).unwrap_or(false);
    info!("[PROXY_AUTH - EVENT] Final authenticated value: {}", is_authenticated);
    
    if is_authenticated {
        // User is authenticated, proxy the request and inject identity headers
        let identity_email = session.get::<String>("email").ok().flatten();
        proxy_request(req, body, identity_email).await
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
                let path_segments: Vec<&str> = original_uri.trim_start_matches('/').split('/').collect();
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
        "/etc/runegate/config/email.toml",  // System-installed path
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
            },
            Err(err) => {
                debug!("Could not load email config from {}: {}", path, err);
                last_error = Some(err);
            }
        }
    }
    
    // Unwrap the configuration or fail with the last error
    let config_text = config_text.unwrap_or_else(|| {
        error!("Failed to load email configuration from any of the specified paths");
        panic!("Failed to read email config file: {:?}", last_error.unwrap());
    });
    
    // Parse the email configuration
    let email_config: EmailConfig = toml::from_str(&config_text)
        .expect("Failed to parse email config");
    
    // Get base URL from environment or use default
    let base_url = std::env::var("RUNEGATE_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:7870".to_string());
    
    AppConfig {
        base_url,
        email_config,
    }
}

/// Get session key from environment or use default
fn get_session_key() -> Key {
    match std::env::var(SESSION_KEY_ENV) {
        Ok(key_str) => {
            let key_str = key_str.trim(); // Remove any whitespace/newlines
            info!("Session key debug: length={}, is_hex={}", key_str.len(), key_str.chars().all(|c| c.is_ascii_hexdigit()));
            
            // Try to decode as hex first (128 hex chars = 64 bytes)
            if key_str.len() == 128 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
                info!("Attempting hex decode of session key");
                match hex::decode(key_str) {
                    Ok(key_bytes) => {
                        if key_bytes.len() == 64 {
                            info!("Successfully decoded hex session key to 64 bytes");
                            return Key::from(&key_bytes);
                        } else {
                            warn!("Hex decoded session key is {} bytes, not 64", key_bytes.len());
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
        Err(_) => {
            match std::env::var(RUNEGATE_ENV).as_deref() {
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
            }
        }
    }
}

/// Log environment configuration with sensitive values redacted
fn log_environment_config() {
    // Environment mode
    let env_mode = std::env::var("RUNEGATE_ENV").unwrap_or_else(|_| "development".to_string());
    info!("🔧 Environment mode: {}", env_mode);
    
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
    let base_url = std::env::var("RUNEGATE_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:7870".to_string());
    info!("🌐 Base URL: {}", base_url);
    
    // Magic link expiry
    let expiry = std::env::var("RUNEGATE_MAGIC_LINK_EXPIRY")
        .unwrap_or_else(|_| "15".to_string());
    info!("⏰ Magic link expiry: {} minutes", expiry);
    
    // Secure cookies
    let secure_cookie = std::env::var("RUNEGATE_SECURE_COOKIE")
        .unwrap_or_else(|_| "auto".to_string());
    info!("🔒 Secure cookies: {}", secure_cookie);
    
    // Cookie domain (optional)
    match std::env::var(RUNEGATE_COOKIE_DOMAIN_VAR) {
        Ok(domain) if !domain.trim().is_empty() => info!("🍪 Cookie domain: {}", domain.trim()),
        _ => info!("🍪 Cookie domain: (unset - host-only)"),
    }
    
    // Rate limiting
    let rate_limit_enabled = std::env::var("RUNEGATE_RATE_LIMIT_ENABLED")
        .unwrap_or_else(|_| "true".to_string());
    info!("🛡️  Rate limiting: {}", rate_limit_enabled);
    
    if rate_limit_enabled == "true" {
        let login_limit = std::env::var("RUNEGATE_LOGIN_RATE_LIMIT")
            .unwrap_or_else(|_| "5".to_string());
        let email_cooldown = std::env::var("RUNEGATE_EMAIL_COOLDOWN")
            .unwrap_or_else(|_| "300".to_string());
        let token_limit = std::env::var("RUNEGATE_TOKEN_RATE_LIMIT")
            .unwrap_or_else(|_| "10".to_string());
        info!("   📊 Login limit: {}/min/IP, Email cooldown: {}s, Token limit: {}/min/IP", 
              login_limit, email_cooldown, token_limit);
    }
    
    // Logging configuration
    let log_format = std::env::var("RUNEGATE_LOG_FORMAT")
        .unwrap_or_else(|_| "console".to_string());
    info!("📝 Log format: {}", log_format);
    // Session cookie name
    let cookie_name = std::env::var(RUNEGATE_SESSION_COOKIE_NAME_VAR)
        .unwrap_or_else(|_| "runegate_id".to_string());
    info!("🍪 Session cookie name: {}", cookie_name);
    // Debug endpoints flag
    let debug_flag = std::env::var(RUNEGATE_DEBUG_ENDPOINTS_VAR).unwrap_or_else(|_| "auto".to_string());
    info!("🧪 Debug endpoints flag: {} (auto=false in production)", debug_flag);
}

/// Load environment file from multiple possible locations
fn load_env_file() {
    // Try multiple locations for the environment file
    // 1. First try the system-installed location (for deployed environments)
    // 2. Then try the local development path
    let env_paths = [
        "/etc/runegate/runegate.env",  // System-installed path
        ".env",                       // Development path
    ];
    
    // Try each path until one works
    for path in &env_paths {
        match dotenvy::from_path(path) {
            Ok(_) => {
                info!("Loaded environment configuration from {}", path);
                return;
            },
            Err(err) => {
                debug!("Could not load environment config from {}: {}", path, err);
            }
        }
    }
    
    // If no .env file found, that's okay - environment variables can still be set directly
    debug!("No .env file found in any of the expected locations, using system environment variables only");
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
    let client_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();
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
                .collect::<Vec<_>>()
        ),
        Err(_e) => None,
    };
    let client_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();

    HttpResponse::Ok().json(serde_json::json!({
        "raw_cookie_header": raw_cookie_header,
        "parsed": parsed,
        "client_ip": client_ip,
    }))
}

/// Debug endpoint that goes through auth middleware to verify auth gating
#[instrument(name = "debug_protected", skip(session))]
async fn debug_protected(session: Session) -> impl Responder {
    let authenticated = session.get::<bool>("authenticated").ok().flatten().unwrap_or(false);
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
    let log_format = std::env::var("RUNEGATE_LOG_FORMAT")
        .unwrap_or_else(|_| "console".to_string());
    
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
    
    // Log environment configuration (redacting sensitive values)
    log_environment_config();
    
    // Load application configuration
    let config = load_config();
    let app_config = web::Data::new(config);
    
    // Set up the session key for cookies
    let session_key = get_session_key();
    // Create a single shared in-memory session store for all workers
    let shared_session_store = MemorySessionStore::new();
    
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

    HttpServer::new(move || {
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
                .wrap(TracingLogger::default())
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
                // API Endpoints - define these first to ensure they take priority
                .service(web::resource("/health").route(web::get().to(health_check)))
                .service(web::resource("/login").route(web::post().to(login)))
                .service(web::resource("/auth").route(web::get().to(auth)))
                .service(web::resource("/rate_limit_info").route(web::get().to(rate_limit_info)));

            if debug_endpoints_enabled {
                app = app
                    .service(web::resource("/debug/session").route(web::get().to(debug_session)))
                    .service(web::resource("/debug/cookies").route(web::get().to(debug_cookies)))
                    .service(web::resource("/debug/protected").route(web::get().to(debug_protected)));
            }

            app
                // Static files serving - place after API endpoints to avoid routing conflicts
                .service(Files::new("/login.html", "static").index_file("login.html"))
                .service(Files::new("/static", "static"))
                .service(Files::new("/img", "static/img"))
                // Protected routes need to be guarded in each handler
                .default_service(web::route().to(auth_check_and_proxy))
        }
    })
    .bind("0.0.0.0:7870")?
    .client_request_timeout(Duration::from_secs(60))
    .workers(4)
    .run()
    .await
}
