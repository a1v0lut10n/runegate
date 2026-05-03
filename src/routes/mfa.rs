use actix_web::{web, HttpResponse, Responder, http::header};
use actix_session::Session;
use tracing::{error, info, instrument};

#[derive(Debug, serde::Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[instrument(name = "mfa_totp_verify", skip(session))]
pub async fn totp_verify(
    req_data: web::Json<TotpVerifyRequest>,
    session: Session,
) -> impl Responder {
    let email = match session.get::<String>("email") {
        Ok(Some(e)) => e,
        _ => return HttpResponse::Unauthorized().json("No preauth session"),
    };

    let _preauth_id = match session.get::<String>("preauth_id") {
        Ok(Some(id)) => id,
        _ => return HttpResponse::Unauthorized().json("No preauth session"),
    };

    // TODO: Actually fetch the user's TOTP secret from IdentityStore and verify.
    // For now, we accept any code "000000" as a bypass for testing before DB is wired up.
    if req_data.code != "000000" {
        return HttpResponse::BadRequest().json("Invalid TOTP code");
    }

    // Upgrade session to fully authenticated
    if let Err(e) = session.insert("authenticated", true) {
        error!("Failed to set authenticated session: {}", e);
        return HttpResponse::InternalServerError().json("Session error");
    }
    
    // Remove the preauth constraint
    session.remove("preauth_id");
    session.renew();

    info!("✅ User {} completed MFA successfully", email);

    HttpResponse::Found()
        .append_header((header::LOCATION, "/proxy/"))
        .finish()
}

#[instrument(name = "mfa_webauthn_start", skip(_session))]
pub async fn webauthn_start(_session: Session) -> impl Responder {
    // TODO: Use webauthn-rs to generate Request Challenge
    HttpResponse::NotImplemented().json("WebAuthn not fully implemented yet")
}

#[instrument(name = "mfa_webauthn_finish", skip(_session))]
pub async fn webauthn_finish(_session: Session) -> impl Responder {
    // TODO: Use webauthn-rs to verify Request Challenge
    HttpResponse::NotImplemented().json("WebAuthn not fully implemented yet")
}
