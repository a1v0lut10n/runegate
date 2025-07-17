// SPDX-License-Identifier: Apache-2.0
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, Error};
use tracing::{info, warn, error, debug, instrument};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::{Key, SameSite};
use actix_web::http::header;
use actix_files::Files;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::fs;
use std::sync::Arc;

use runegate::email::EmailConfig;
use runegate::send_magic_link::send_magic_link;
use runegate::auth::{generate_magic_link, verify_token, get_magic_link_expiry, JWT_SECRET_ENV};
use runegate::proxy::{proxy_request, TARGET_SERVICE_ENV};
use runegate::logging;
use runegate::middleware::AuthMiddleware;
use runegate::rate_limit::RateLimiters;
use tracing_actix_web::TracingLogger;
use rand::Rng; // Added for random key generation

// Application configuration constants
const SESSION_KEY_ENV: &str = "RUNEGATE_SESSION_KEY";
const RUNEGATE_ENV: &str = "RUNEGATE_ENV"; // Environment variable to check for production mode
const RUNEGATE_SECURE_COOKIE_VAR: &str = "RUNEGATE_SECURE_COOKIE";

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
    HttpResponse::Ok().json("Runegate is running")
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
    match send_magic_link(&app_config.email_config, email, &login_url) {
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
            session.insert("authenticated", true).ok();
            session.insert("email", email.clone()).ok();
            // Redirect to the home page after successful auth
            HttpResponse::Found()
                .append_header((header::LOCATION, "/"))
                .json(format!("Authentication successful for {}", email))
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
    let is_authenticated = session.get::<bool>("authenticated").unwrap_or(None).unwrap_or(false);
    
    if is_authenticated {
        // User is authenticated, proxy the request
        proxy_request(req, body).await
    } else {
        // User is not authenticated, redirect to login
        Ok(HttpResponse::Found()
            .append_header((header::LOCATION, "/login.html"))
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
            let key_bytes = key_str.as_bytes();
            if key_bytes.len() < 64 {
                error!(
                    "RUNEGATE_SESSION_KEY is set but is less than 64 bytes ({} bytes). This is insecure.",
                    key_bytes.len()
                );
                panic!("RUNEGATE_SESSION_KEY must be at least 64 bytes.");
            }
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

/// Diagnostic endpoint to return the current rate limiting configuration
#[instrument(name = "rate_limit_info")]
async fn rate_limit_info(rate_limiters: web::Data<Arc<RateLimiters>>) -> impl Responder {
    let rate_limit_config = rate_limiters.config.clone();
    HttpResponse::Ok().json(rate_limit_config)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env file if present
    dotenvy::dotenv().ok();
    
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
    info!("🚪 Starting Runegate auth proxy...");
    if std::env::var(JWT_SECRET_ENV).is_err() {
        warn!("⚠️  No JWT secret set in environment. Using development default.");
    }
    if std::env::var(SESSION_KEY_ENV).is_err() {
        warn!("⚠️  No session key set in environment. Using development default.");
    }
    if std::env::var(TARGET_SERVICE_ENV).is_err() {
        info!("ℹ️  No target service URL set. Defaulting to localhost:7870.");
    }
    
    // Load application configuration
    let config = load_config();
    let app_config = web::Data::new(config);
    
    // Set up the session key for cookies
    let session_key = get_session_key();
    
    // Create shared data for rate limiters
    let rate_limiters_data = web::Data::new(rate_limiters.clone());
    
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

        App::new()
            .wrap(TracingLogger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_secure(secure_cookie)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .build()
            )
            // Static files serving
            .service(Files::new("/login.html", "static").index_file("login.html"))
            .service(Files::new("/", "static"))
            // No rate limiting middleware - we'll use direct checks in the handlers
            // Auth middleware
            .wrap(AuthMiddleware::new())
            // App data
            .app_data(app_config.clone())
            .app_data(rate_limiters_data.clone())
            // API Endpoints
            .service(web::resource("/health").route(web::get().to(health_check)))
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/auth").route(web::get().to(auth)))
            .service(web::resource("/rate_limit_info").route(web::get().to(rate_limit_info)))
            // Protected routes need to be guarded in each handler
            .default_service(web::route().to(auth_check_and_proxy))
    })
    .bind("0.0.0.0:7870")?
    .client_request_timeout(Duration::from_secs(60))
    .workers(4)
    .run()
    .await
}
