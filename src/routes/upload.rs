use actix_session::Session;
use actix_web::{HttpResponse, Responder, web};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, instrument};

use crate::config::AppConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadTicketClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

#[instrument(name = "create_upload_ticket", skip(session, app_config))]
pub async fn create_upload_ticket(
    session: Session,
    app_config: web::Data<AppConfig>,
) -> impl Responder {
    let email = match session.get::<String>("email") {
        Ok(Some(e)) => e,
        _ => return HttpResponse::Unauthorized().json("Not authenticated"),
    };

    let authenticated = session
        .get::<bool>("authenticated")
        .unwrap_or(Some(false))
        .unwrap_or(false);
    if !authenticated {
        return HttpResponse::Forbidden().json("Requires full session authentication");
    }

    let private_key_pem = match &app_config.upload_private_key {
        Some(key) => key,
        None => {
            return HttpResponse::NotImplemented()
                .json("Upload tickets are not configured on this server");
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Short-lived ticket (e.g., 15 minutes)
    let claims = UploadTicketClaims {
        sub: email.clone(),
        iat: now,
        exp: now + (15 * 60),
    };

    let header = Header::new(Algorithm::RS256);
    // Optional: Add kid here if we have multiple keys
    // header.kid = Some("upload-key-1".to_string());

    let encoding_key = match EncodingKey::from_rsa_pem(private_key_pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to parse upload private key: {}", e);
            return HttpResponse::InternalServerError().json("Configuration error");
        }
    };

    match encode(&header, &claims, &encoding_key) {
        Ok(token) => {
            info!("🎟️ Minted upload ticket for user {}", email);
            HttpResponse::Ok().json(serde_json::json!({
                "ticket": token,
                "expires_in": 900
            }))
        }
        Err(e) => {
            error!("Failed to encode upload ticket: {}", e);
            HttpResponse::InternalServerError().json("Failed to generate ticket")
        }
    }
}

#[instrument(name = "get_upload_jwks", skip(app_config))]
pub async fn get_upload_jwks(app_config: web::Data<AppConfig>) -> impl Responder {
    match &app_config.upload_jwks {
        Some(jwks_json) => {
            // Parse and return as raw JSON to ensure proper content-type
            match serde_json::from_str::<serde_json::Value>(jwks_json) {
                Ok(val) => HttpResponse::Ok().json(val),
                Err(e) => {
                    error!("Invalid JWKS JSON in config: {}", e);
                    HttpResponse::InternalServerError().json("Configuration error")
                }
            }
        }
        None => HttpResponse::NotImplemented().json("JWKS is not configured on this server"),
    }
}
