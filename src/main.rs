use runegate::email::EmailConfig;
use std::fs;

use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    email: String,
}

async fn login(login_data: web::Json<LoginRequest>) -> impl Responder {
    // TODO: Implement the login endpoint that sends a magic link
    HttpResponse::Ok().json(format!("Login request for: {}", login_data.email))
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json("Runegate is running")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚪 Starting Runegate auth proxy...");
    
    // TODO: Load configuration from email.toml
    
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health_check))
            .route("/login", web::post().to(login))
            // Add more routes here
    })
    .bind("127.0.0.1:7870")?
    .run()
    .await
}
