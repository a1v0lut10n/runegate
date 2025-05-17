use actix_web::{
    web, HttpRequest, HttpResponse, Error,
    http::{header, StatusCode},
};
use awc::Client;
use tracing::{error, debug, instrument};

/// Environment variable for the target service URL
pub const TARGET_SERVICE_ENV: &str = "RUNEGATE_TARGET_SERVICE";
// Default target service URL if not set
const DEFAULT_TARGET_SERVICE: &str = "http://127.0.0.1:7860";

/// Proxy a request to the target service
#[instrument(skip(body), fields(method = %req.method(), path = %req.uri().path(), query = %req.uri().query().unwrap_or(""), client_ip = %req.connection_info().realip_remote_addr().unwrap_or("unknown")))]
pub async fn proxy_request(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, Error> {
    let target_url = get_target_service_url();
    
    // Build the forwarded URL
    let path = req.uri().path();
    let query = req.uri().query().map_or_else(String::new, |q| format!("?{}", q));
    let forwarded_url = format!("{}{}{}", target_url, path, query);
    
    debug!(target_url = %target_url, forwarded_url = %forwarded_url, "Proxying request");
    
    // Create a client to forward the request
    let client = Client::default();
    
    // Build the request to pass through
    let mut forwarded_req = client
        .request(req.method().clone(), forwarded_url)
        .no_decompress();
    
    // Copy original headers, excluding ones that would cause issues
    for (header_name, header_value) in req.headers().iter().filter(|(h, _)| 
        *h != header::HOST && 
        *h != header::CONNECTION && 
        *h != header::CONTENT_LENGTH
    ) {
        forwarded_req = forwarded_req.insert_header((header_name.clone(), header_value.clone()));
    }
    
    // Forward the original client IP if available
    if let Some(client_ip) = req.connection_info().realip_remote_addr() {
        forwarded_req = forwarded_req.insert_header((header::FORWARDED, format!("for={}", client_ip)));
    }
    
    // Add the body if it exists
    let forwarded_req = if !body.is_empty() {
        // Convert actix body to awc body
        forwarded_req.send_body(body)
    } else {
        forwarded_req.send()
    };
    
    // Send the request to the target service
    let mut forwarded_res = forwarded_req.await.map_err(|e| {
        error!(error = %e, "Forwarding error to target service");
        actix_web::error::ErrorBadGateway(e)
    })?;
    
    debug!(status = %forwarded_res.status(), "Received response from target service");
    
    // Build a response to send back to the client
    let mut client_res = HttpResponse::build(StatusCode::from_u16(
        forwarded_res.status().as_u16()
    ).unwrap_or(StatusCode::BAD_GATEWAY));
    
    // Copy response headers
    for (header_name, header_value) in forwarded_res.headers().iter().filter(|(h, _)| 
        *h != header::CONNECTION && 
        *h != header::CONTENT_LENGTH &&
        *h != header::TRANSFER_ENCODING
    ) {
        client_res.insert_header((header_name.clone(), header_value.clone()));
    }
    
    // Get the response body
    let body = forwarded_res.body().await.map_err(|e| {
        error!(error = %e, "Failed to read response body from target service");
        actix_web::error::ErrorBadGateway(e)
    })?;
    
    debug!(body_size = body.len(), "Returning response to client");
    
    // Return the complete response
    Ok(client_res.body(body))
}

/// Gets the target service URL from environment or uses default
#[instrument]
fn get_target_service_url() -> String {
    std::env::var(TARGET_SERVICE_ENV).unwrap_or_else(|_| DEFAULT_TARGET_SERVICE.to_string())
}
