use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, Error};
use tracing::{info, warn, instrument};
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
use runegate::auth::{generate_magic_link, verify_token, JWT_SECRET_ENV};
use runegate::proxy::{proxy_request, TARGET_SERVICE_ENV};
use runegate::logging;
use runegate::middleware::AuthMiddleware;
use runegate::rate_limit::RateLimiters;
use tracing_actix_web::TracingLogger;

// Application configuration constants
const SESSION_KEY_ENV: &str = "RUNEGATE_SESSION_KEY";
// Ensure the key is at least 64 bytes for proper security
const DEFAULT_SESSION_KEY: &[u8] = b"runegate_development_session_key_please_change_this_is_not_secure_enough_for_production_use_a_better_key";
const MAGIC_LINK_EXPIRY_MINUTES: u64 = 15;

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
            .json("Too many login attempts from this IP address. Please try again later.");
    }
    
    // Check if this email is rate-limited (cooldown between magic link requests)
    if let Some(remaining_seconds) = rate_limiters.email_limiter.check_email(email) {
        warn!("Rate limited attempt to send magic link to {}, cooldown: {} seconds", email, remaining_seconds);
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Reset", remaining_seconds.to_string()))
            .json(format!("Please wait {} seconds before requesting another magic link", remaining_seconds));
    }
    
    // Generate a magic link with JWT token
    let login_url = generate_magic_link(email, base_url, MAGIC_LINK_EXPIRY_MINUTES);
    
    // Send the email
    match send_magic_link(&app_config.email_config, email, &login_url) {
        Ok(_) => {
            info!("📧 Magic link sent to {}", email);
            HttpResponse::Ok().json(format!("Magic link sent to {}", email))
        },
        Err(e) => {
            warn!("Failed to send magic link: {}", e);
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
    // Load email config from config/email.toml
    let config_text = fs::read_to_string("config/email.toml")
        .expect("Failed to read email config file");
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
        Ok(key) => Key::from(key.as_bytes()),
        Err(_) => Key::from(DEFAULT_SESSION_KEY),
    }
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
        App::new()
            .wrap(TracingLogger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_secure(false)  // Set to true in production with HTTPS
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .build()
            )
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
            // Static files serving
            .service(Files::new("/login.html", "static").index_file("login.html"))
            .service(Files::new("/", "static"))
            // Protected routes need to be guarded in each handler
            .default_service(web::route().to(auth_check_and_proxy))
    })
    .bind("0.0.0.0:7870")?
    .client_request_timeout(Duration::from_secs(60))
    .workers(4)
    .run()
    .await
}
