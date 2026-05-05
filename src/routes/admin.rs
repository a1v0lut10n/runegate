use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};
use uuid::Uuid;
use std::env;

use crate::store::pg::PgStore;

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: i32,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub id: Uuid,
    pub code: String,
    pub max_uses: i32,
    pub is_revoked: bool,
}

fn check_admin_token(req: &HttpRequest) -> bool {
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => return false,
    };

    if !auth_header.starts_with("Bearer ") {
        return false;
    }

    let token = &auth_header[7..];
    let expected_token = match env::var("RUNEGATE_ADMIN_API_TOKEN") {
        Ok(t) => t,
        Err(_) => return false, // Admin API disabled if no token set
    };

    // Constant-time compare to prevent timing attacks
    use constant_time_eq::constant_time_eq;
    constant_time_eq(token.as_bytes(), expected_token.as_bytes())
}

#[instrument(name = "admin_create_invite", skip(req, pg_store))]
pub async fn create_invite(
    req: HttpRequest,
    req_body: web::Json<CreateInviteRequest>,
    pg_store: web::Data<PgStore>,
) -> impl Responder {
    if !check_admin_token(&req) {
        return HttpResponse::Unauthorized().json("Unauthorized admin access");
    }

    // Generate a random 12-character alphanumeric code
    use rand::RngExt;
    let code: String = rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    match pg_store.create_admin_invite(&code, req_body.max_uses).await {
        Ok(invite) => {
            info!("Created invite code: {}", invite.code);
            HttpResponse::Ok().json(InviteResponse {
                id: invite.id,
                code: invite.code,
                max_uses: invite.max_uses,
                is_revoked: invite.is_revoked,
            })
        }
        Err(e) => {
            error!("Failed to create invite: {}", e);
            HttpResponse::InternalServerError().json("Database error")
        }
    }
}

#[instrument(name = "admin_get_invites", skip(req, _pg_store))]
pub async fn get_invites(
    req: HttpRequest,
    _pg_store: web::Data<PgStore>,
) -> impl Responder {
    if !check_admin_token(&req) {
        return HttpResponse::Unauthorized().json("Unauthorized admin access");
    }

    // This is a placeholder since get_all_invites wasn't strictly required in the schema, 
    // but the route exists. Returning Not Implemented for now.
    HttpResponse::NotImplemented().json("Get invites list not fully implemented yet")
}

#[instrument(name = "admin_revoke_invite", skip(req, pg_store))]
pub async fn revoke_invite(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pg_store: web::Data<PgStore>,
) -> impl Responder {
    if !check_admin_token(&req) {
        return HttpResponse::Unauthorized().json("Unauthorized admin access");
    }

    let invite_id = path.into_inner();

    match pg_store.revoke_invite(invite_id).await {
        Ok(_) => {
            info!("Revoked invite: {}", invite_id);
            HttpResponse::Ok().json("Invite revoked successfully")
        }
        Err(e) => {
            error!("Failed to revoke invite: {}", e);
            HttpResponse::InternalServerError().json("Database error")
        }
    }
}
