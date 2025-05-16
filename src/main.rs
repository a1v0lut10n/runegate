use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, middleware, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::{Key, SameSite};
use actix_web::http::header;
use actix_files::Files;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::fs;

use runegate::email::EmailConfig;
use runegate::send_magic_link::send_magic_link;
use runegate::auth::{generate_magic_link, verify_token, JWT_SECRET_ENV};
use runegate::proxy::{proxy_request, TARGET_SERVICE_ENV};
// Middleware impl will be added later

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
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json("Runegate is running")
}

/// Login endpoint that sends a magic link via email
async fn login(login_data: web::Json<LoginRequest>, app_config: web::Data<AppConfig>) -> impl Responder {
    let email = &login_data.email;
    let base_url = &app_config.base_url;
    
    // Generate a magic link with JWT token
    let login_url = generate_magic_link(email, base_url, MAGIC_LINK_EXPIRY_MINUTES);
    
    // Send the email
    match send_magic_link(&app_config.email_config, email, &login_url) {
        Ok(_) => {
            println!("📧 Magic link sent to {}", email);
            HttpResponse::Ok().json(format!("Magic link sent to {}", email))
        },
        Err(e) => {
            eprintln!("Failed to send magic link: {}", e);
            HttpResponse::InternalServerError().json("Failed to send login email")
        }
    }
}

/// Auth endpoint that verifies a token from the magic link
async fn auth(req: HttpRequest, session: actix_session::Session) -> impl Responder {
    // Extract token from query string
    let token = match req.query_string().split('=').nth(1) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().json("Missing token")
    };
    
    // Verify the token
    match verify_token(token) {
        Ok(email) => {
            // Set session data
            session.insert("user_email", email.clone()).ok();
            session.insert("authenticated", true).ok();
            
            // Redirect to the home page after successful auth
            HttpResponse::Found()
                .append_header((header::LOCATION, "/"))
                .finish()
        },
        Err(e) => {
            eprintln!("Token verification failed: {}", e);
            HttpResponse::Unauthorized().json("Invalid or expired login link")
        }
    }
}

/// Middleware to check if user is authenticated
async fn auth_middleware(req: HttpRequest, session: actix_session::Session) -> Result<HttpResponse, Error> {
    // Skip auth check for login and auth endpoints
    let path = req.path();
    if path == "/login" || path == "/health" || path.starts_with("/auth") {
        return Ok(HttpResponse::Ok().finish()); // Allow access to public endpoints
    }
    
    // Check if user is authenticated
    match session.get::<bool>("authenticated") {
        Ok(Some(true)) => Ok(HttpResponse::Ok().finish()), // User is authenticated, allow access
        _ => {
            // Redirect to login page
            Ok(HttpResponse::Found()
                .append_header((header::LOCATION, "/login"))
                .finish())
        }
    }
}

/// Proxy handler for all authenticated requests
async fn proxy(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, Error> {
    proxy_request(req, body).await
}

/// Authentication check and proxy handler
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
    
    // Print configuration information
    println!("🚪 Starting Runegate auth proxy...");
    if std::env::var(JWT_SECRET_ENV).is_err() {
        println!("⚠️  No JWT secret set in environment. Using development default.");
    }
    if std::env::var(SESSION_KEY_ENV).is_err() {
        println!("⚠️  No session key set in environment. Using development default.");
    }
    if std::env::var(TARGET_SERVICE_ENV).is_err() {
        println!("ℹ️  No target service URL set. Defaulting to localhost:7870.");
    }
    
    // Load application configuration
    let config = load_config();
    let app_config = web::Data::new(config);
    
    // Set up the session key for cookies
    let session_key = get_session_key();
    
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_secure(false)  // Set to true in production with HTTPS
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .build()
            )
            .app_data(app_config.clone())
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
