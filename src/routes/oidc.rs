use actix_web::{web, HttpResponse, Responder, http::header};
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
    TokenUrl,
};
use oauth2::basic::BasicClient;
use crate::config::AppConfig;
use actix_session::Session;
use tracing::{error, info, instrument};

#[instrument(name = "google_start", skip(session, app_config))]
pub async fn google_start(
    session: Session,
    app_config: web::Data<AppConfig>,
) -> impl Responder {
    let oidc_config = match app_config.google_oidc.as_ref() {
        Some(config) => config,
        None => return HttpResponse::InternalServerError().json("Google OIDC not configured"),
    };

    let client = BasicClient::new(ClientId::new(oidc_config.client_id.clone()))
        .set_client_secret(ClientSecret::new(oidc_config.client_secret.clone()))
        .set_auth_uri(AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap())
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap())
        .set_redirect_uri(RedirectUrl::new(oidc_config.redirect_url.clone()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store csrf_token and pkce_verifier in session
    if let Err(e) = session.insert("oidc_csrf", csrf_token.secret().to_string()) {
        error!("Failed to save CSRF token to session: {}", e);
        return HttpResponse::InternalServerError().json("Session error");
    }
    if let Err(e) = session.insert("oidc_pkce", pkce_verifier.secret().to_string()) {
        error!("Failed to save PKCE verifier to session: {}", e);
        return HttpResponse::InternalServerError().json("Session error");
    }

    HttpResponse::Found()
        .append_header((header::LOCATION, auth_url.to_string()))
        .finish()
}

#[derive(Debug, serde::Deserialize)]
pub struct AuthCallback {
    pub code: String,
    pub state: String,
}

#[instrument(name = "google_callback", skip(session, app_config, pg_store))]
pub async fn google_callback(
    query: web::Query<AuthCallback>,
    session: Session,
    app_config: web::Data<AppConfig>,
    pg_store: Option<web::Data<crate::store::pg::PgStore>>,
) -> impl Responder {
    let oidc_config = match app_config.google_oidc.as_ref() {
        Some(config) => config,
        None => return HttpResponse::InternalServerError().json("Google OIDC not configured"),
    };

    let client = BasicClient::new(ClientId::new(oidc_config.client_id.clone()))
        .set_client_secret(ClientSecret::new(oidc_config.client_secret.clone()))
        .set_auth_uri(AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap())
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap())
        .set_redirect_uri(RedirectUrl::new(oidc_config.redirect_url.clone()).unwrap());

    let stored_csrf = match session.get::<String>("oidc_csrf") {
        Ok(Some(s)) => s,
        _ => return HttpResponse::BadRequest().json("Missing CSRF token in session"),
    };

    if query.state != stored_csrf {
        return HttpResponse::BadRequest().json("Invalid CSRF state");
    }

    let pkce_secret = match session.get::<String>("oidc_pkce") {
        Ok(Some(s)) => s,
        _ => return HttpResponse::BadRequest().json("Missing PKCE verifier in session"),
    };
    let pkce_verifier = oauth2::PkceCodeVerifier::new(pkce_secret);

    use oauth2::TokenResponse;
    use oauth2::AuthorizationCode;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await;

    let token = match token_result {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to exchange token: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to exchange auth code");
        }
    };

    // We have the access token, now we need to fetch user profile to get email.
    let access_token = token.access_token().secret();
    
    let res = http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await;
        
    let user_info = match res {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(json) => json,
            Err(_) => return HttpResponse::InternalServerError().json("Failed to parse userinfo"),
        },
        Err(_) => return HttpResponse::InternalServerError().json("Failed to fetch userinfo"),
    };
    
    let email = match user_info.get("email").and_then(|v| v.as_str()) {
        Some(e) => e.to_string(),
        None => return HttpResponse::BadRequest().json("No email provided by Google"),
    };

    if let Some(store) = &pg_store {
        if std::env::var("RUNEGATE_SIGNUP_POLICY").as_deref() == Ok("invite_only") {
            let user = store.get_user_by_email(&email).await.unwrap_or(None);
            if user.is_none() {
                return HttpResponse::Forbidden().json("Sign up is currently invite-only. Please use an invite code on the main login page.");
            }
        } else {
            // Open signup: create user if they don't exist
            if store.get_user_by_email(&email).await.unwrap_or(None).is_none() {
                let _ = store.create_user(&email).await;
            }
        }
    }

    // Initialize authenticated session directly
    if let Err(e) = session.insert("authenticated", true) {
        error!("Failed to set authenticated session: {}", e);
        return HttpResponse::InternalServerError().json("Session error");
    }
    if let Err(e) = session.insert("email", email.clone()) {
        error!("Failed to set email in session: {}", e);
        return HttpResponse::InternalServerError().json("Session error");
    }
    
    // Clear out OIDC temporaries
    session.remove("oidc_csrf");
    session.remove("oidc_pkce");

    session.renew();

    info!("✅ User {} authenticated successfully via Google", email);

    let redirect_path = std::env::var("RUNEGATE_DEFAULT_REDIRECT")
        .unwrap_or_else(|_| "/proxy/".to_string());
    HttpResponse::Found()
        .append_header((header::LOCATION, redirect_path))
        .finish()
}
