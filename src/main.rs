// SPDX-License-Identifier: Apache-2.0
use actix_session::SessionMiddleware;
use actix_web::cookie::{Key, SameSite};
use actix_web::middleware::Condition;
use actix_web::{App, HttpServer, web};

use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use rand::RngExt;
use runegate::app::{AppSettings, build_renderer, configure_routes};
use runegate::config::{AppConfig, AuthUiMode, RunegateMode};
use runegate::email::EmailConfig;
use runegate::logging;
use runegate::memory_session_store::MemorySessionStore;
use runegate::middleware::AuthMiddleware;
use runegate::rate_limit::RateLimiters;
use runegate::store::pg::PgStore;
use tracing_actix_web::TracingLogger;

// Application configuration constants
const SESSION_KEY_ENV: &str = "RUNEGATE_SESSION_KEY";
const RUNEGATE_ENV: &str = "RUNEGATE_ENV"; // Environment variable to check for production mode
const RUNEGATE_SECURE_COOKIE_VAR: &str = "RUNEGATE_SECURE_COOKIE";
const RUNEGATE_COOKIE_DOMAIN_VAR: &str = "RUNEGATE_COOKIE_DOMAIN";
const RUNEGATE_SESSION_COOKIE_NAME_VAR: &str = "RUNEGATE_SESSION_COOKIE_NAME";
const RUNEGATE_DEBUG_ENDPOINTS_VAR: &str = "RUNEGATE_DEBUG_ENDPOINTS";

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

    let google_oidc = if let (Ok(client_id), Ok(client_secret), Ok(redirect_url)) = (
        std::env::var("RUNEGATE_GOOGLE_CLIENT_ID"),
        std::env::var("RUNEGATE_GOOGLE_CLIENT_SECRET"),
        std::env::var("RUNEGATE_GOOGLE_REDIRECT_URL"),
    ) {
        info!("Google OIDC configuration loaded successfully from environment");
        Some(runegate::config::OidcConfig {
            client_id,
            client_secret,
            redirect_url,
        })
    } else {
        debug!("Google OIDC environment variables not fully configured; SSO disabled");
        None
    };

    AppConfig {
        base_url,
        email_config,
        google_oidc,
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
    let runegate_mode = std::env::var(runegate::config::RUNEGATE_MODE_ENV)
        .unwrap_or_else(|_| "magic-link-only".to_string());
    info!("🔄 Runegate mode: {}", runegate_mode);

    // Auth UI mode (static, phenotyper, external)
    let ui_mode = std::env::var(runegate::config::RUNEGATE_AUTH_UI_MODE_ENV)
        .unwrap_or_else(|_| "static".to_string());
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

    let runegate_mode = RunegateMode::from_env();
    info!("🚀 Operating in {:?} mode", runegate_mode);

    let auth_ui_mode = AuthUiMode::from_env();
    info!("🎨 Auth UI configured for {:?} mode", auth_ui_mode);

    // Initialize Auth UI Renderer
    let renderer = build_renderer(auth_ui_mode);
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

    let app_settings = AppSettings {
        mode: runegate_mode,
        debug_endpoints_enabled,
    };
    let app_settings_data = web::Data::new(app_settings);

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

        let mut app = App::new()
            // Access logging (gate by env; default off in production)
            .wrap(Condition::new(request_logs_enabled, TracingLogger::default()))
            // Ensure SessionMiddleware runs before AuthMiddleware so session is available in auth checks
            .wrap(AuthMiddleware::with_mode(app_settings.mode))
            .wrap(
                SessionMiddleware::builder(shared_session_store.clone(), session_key.clone())
                    .cookie_secure(secure_cookie)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .cookie_path("/".to_string())
                    .cookie_domain(cookie_domain_opt)
                    .cookie_name(session_cookie_name.clone())
                    .build(),
            )
            // App data
            .app_data(app_config.clone())
            .app_data(rate_limiters_data.clone())
            .app_data(renderer_data.clone())
            .app_data(app_settings_data.clone());

        if let Some(pg) = &pg_store_instance {
            app = app.app_data(web::Data::new(pg.clone()));
        }

        app.configure(|cfg| configure_routes(cfg, &app_settings))
    })
    .bind("0.0.0.0:7870")?
    .client_request_timeout(Duration::from_secs(600))
    .keep_alive(Duration::from_secs(15))
    .backlog(2048)
    .workers(workers)
    .run()
    .await
}
