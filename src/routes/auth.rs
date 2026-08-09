use crate::{
    auth::{generate_magic_link, get_magic_link_expiry, verify_token},
    config::AppConfig,
    rate_limit::RateLimiters,
    send_magic_link::send_magic_link,
};
use actix_web::{HttpRequest, HttpResponse, Responder, http::header, web};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, Deserialize)]
pub struct IdentifyRequest {
    pub email: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MagicStartRequest {
    pub email: String,
}

#[instrument(name = "identify", skip(_rate_limiters, pg_store))]
pub async fn identify(
    identify_data: web::Json<IdentifyRequest>,
    _app_config: web::Data<AppConfig>,
    _rate_limiters: web::Data<Arc<RateLimiters>>,
    pg_store: Option<web::Data<crate::store::pg::PgStore>>,
    _req: HttpRequest,
) -> impl Responder {
    let email = &identify_data.email;
    let invite_code = identify_data.invite_code.as_deref();

    if let Some(store) = &pg_store {
        if std::env::var("RUNEGATE_SIGNUP_POLICY").as_deref() == Ok("invite_only") {
            let user = store.get_user_by_email(email).await.unwrap_or(None);
            if user.is_none() {
                // User does not exist. Check invite code.
                match invite_code {
                    Some(code) => {
                        let invite = store.get_invite_by_code(code).await.unwrap_or(None);
                        match invite {
                            Some(inv) => match store.create_user(email).await {
                                Ok(new_user) => {
                                    if let Err(e) = store.consume_invite(inv.id, new_user.id).await
                                    {
                                        error!("Failed to consume invite: {}", e);
                                        return HttpResponse::InternalServerError()
                                            .json("Failed to process invite");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to create user: {}", e);
                                    return HttpResponse::InternalServerError()
                                        .json("Database error");
                                }
                            },
                            None => {
                                return HttpResponse::Forbidden()
                                    .json("Invalid or expired invite code.");
                            }
                        }
                    }
                    None => {
                        return HttpResponse::Forbidden()
                            .json("An invite code is required to sign up.");
                    }
                }
            }
        } else {
            // Open signup: create user if they don't exist
            if store
                .get_user_by_email(email)
                .await
                .unwrap_or(None)
                .is_none()
            {
                let _ = store.create_user(email).await;
            }
        }
    }
    // For now, Identify just forwards to magic_start logic, returning success immediately.
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "methods": ["magic_link"],
        "message": "User identified."
    }))
}

#[instrument(name = "magic_start", skip(rate_limiters, pg_store))]
pub async fn magic_start(
    req_data: web::Json<MagicStartRequest>,
    app_config: web::Data<AppConfig>,
    rate_limiters: web::Data<Arc<RateLimiters>>,
    pg_store: Option<web::Data<crate::store::pg::PgStore>>,
    req: HttpRequest,
) -> impl Responder {
    let email = &req_data.email;
    let base_url = &app_config.base_url;

    if let Some(store) = &pg_store {
        if std::env::var("RUNEGATE_SIGNUP_POLICY").as_deref() == Ok("invite_only") {
            let user = store.get_user_by_email(email).await.unwrap_or(None);
            if user.is_none() {
                return HttpResponse::Forbidden().json("Sign up is currently invite-only. Please use an invite code on the main login page.");
            }
        } else {
            // Open signup: create user if they don't exist
            if store
                .get_user_by_email(email)
                .await
                .unwrap_or(None)
                .is_none()
            {
                let _ = store.create_user(email).await;
            }
        }
    }

    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    if !rate_limiters.login_limiter.check_ip(&client_ip) {
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "IP"))
            .append_header(("X-RateLimit-Reset", "60"))
            .json("Too many login attempts from this IP address. Please try again later.");
    }

    if let Some(remaining_seconds) = rate_limiters.email_limiter.check_email(email) {
        warn!(
            "Rate limited attempt to send magic link to {}, cooldown: {} seconds",
            email, remaining_seconds
        );
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "Email"))
            .append_header(("X-RateLimit-Reset", remaining_seconds.to_string()))
            .json(format!(
                "Please wait {} seconds before requesting another magic link",
                remaining_seconds
            ));
    }

    let expiry_minutes = get_magic_link_expiry();
    let jti = uuid::Uuid::new_v4().to_string();
    let login_url = match generate_magic_link(email, base_url, expiry_minutes, &jti) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to generate magic link: {}", e);
            return HttpResponse::InternalServerError()
                .json("Failed to generate magic link due to internal error.");
        }
    };

    info!(
        "📧 Magic link generated with {} minutes expiry. URL: {}",
        expiry_minutes, login_url
    );

    match send_magic_link(&app_config.email_config, email, &login_url, expiry_minutes) {
        Ok(_) => {
            info!("📧 Magic link sent to {}", email);
            HttpResponse::Ok().json(format!("Magic link sent to {}", email))
        }
        Err(e) => {
            warn!(
                "Failed to send magic link email (falling back to stdout/log display): {}",
                e
            );
            info!("📧 [DEV/FALLBACK] Magic link for {}: {}", email, login_url);
            HttpResponse::Ok().json("Magic link generated (check server logs/email)")
        }
    }
}

#[instrument(name = "magic_consume", skip(session, rate_limiters))]
pub async fn magic_consume(
    req: HttpRequest,
    session: actix_session::Session,
    rate_limiters: web::Data<Arc<RateLimiters>>,
) -> impl Responder {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    if !rate_limiters.token_limiter.check_ip(&client_ip) {
        return HttpResponse::TooManyRequests()
            .append_header(("X-RateLimit-Exceeded", "IP"))
            .append_header(("X-RateLimit-Reset", "60"))
            .json("Too many token verification attempts from this IP. Please try again later.");
    }

    let token = match req.query_string().strip_prefix("token=") {
        Some(token) => token,
        None => return HttpResponse::BadRequest().json("No token provided"),
    };

    match verify_token(token) {
        Ok(verified_token) => {
            let email = verified_token.sub;
            let jti = verified_token.jti;

            // TODO: Ensure JTI is not used twice using RedisStore

            debug!(
                "[AUTH_FLOW] About to set PREAUTH session data for user: {}",
                email
            );

            if let Err(e) = session.insert("preauth_id", jti.clone()) {
                error!("Failed to set preauth session: {}", e);
                return HttpResponse::InternalServerError().json("Session error");
            }
            if let Err(e) = session.insert("authenticated", true) {
                error!("Failed to set authenticated session: {}", e);
                return HttpResponse::InternalServerError().json("Session error");
            }
            if let Err(e) = session.insert("email", email.clone()) {
                error!("Failed to set email in session: {}", e);
                return HttpResponse::InternalServerError().json("Session error");
            }

            session.renew();

            info!("✅ User {} pre-authenticated successfully", email);

            // Redirect to proxy or MFA depending on Gateway mode
            let redirect_path = crate::config::default_redirect();
            HttpResponse::Found()
                .append_header((header::LOCATION, redirect_path))
                .finish()
        }
        Err(err) => {
            warn!("Token validation error: {}", err);
            HttpResponse::Unauthorized().json("Invalid or expired login link")
        }
    }
}
