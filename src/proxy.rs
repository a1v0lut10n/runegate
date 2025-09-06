// SPDX-License-Identifier: Apache-2.0
use actix_web::{
    web, HttpRequest, HttpResponse, Error,
    http::{header, StatusCode, Method},
};
// awc HTTP client; use ClientBuilder for custom timeouts
use std::time::Duration;
use futures::TryStreamExt;
use tracing::{error, debug, instrument};

/// Environment variable for the target service URL
pub const TARGET_SERVICE_ENV: &str = "RUNEGATE_TARGET_SERVICE";
// Default target service URL if not set
const DEFAULT_TARGET_SERVICE: &str = "http://127.0.0.1:7860";

/// Proxy a request to the target service
#[instrument(skip(payload), fields(method = %req.method(), path = %req.uri().path(), query = %req.uri().query().unwrap_or(""), client_ip = %req.connection_info().realip_remote_addr().unwrap_or("unknown")))]
pub async fn proxy_request(req: HttpRequest, payload: web::Payload, identity_email: Option<String>) -> Result<HttpResponse, Error> {
    let target_url = get_target_service_url();
    let session_cookie_name = std::env::var("RUNEGATE_SESSION_COOKIE_NAME").unwrap_or_else(|_| "runegate_id".to_string());
    let identity_headers_enabled = std::env::var("RUNEGATE_IDENTITY_HEADERS")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes" | "on"))
        .unwrap_or(true);
    
    // Build the forwarded URL
    let original_path = req.uri().path();
    // If the request path is under /proxy, strip that prefix when forwarding
    // so that /proxy/* maps to the target service root /*
    let stripped = original_path.strip_prefix("/proxy").unwrap_or(original_path);
    let forwarded_path = if stripped.is_empty() { "/" } else { stripped };
    let query = req.uri().query().map_or_else(String::new, |q| format!("?{}", q));
    let forwarded_url = format!("{}{}{}", target_url, forwarded_path, query);
    
    debug!(target_url = %target_url, forwarded_url = %forwarded_url, "Proxying request");
    
    // Create a client to forward the request with generous timeout for large uploads
    let connector = awc::Connector::new()
        .timeout(Duration::from_secs(10))
        .conn_keep_alive(Duration::from_secs(15))
        .disconnect_timeout(Duration::from_secs(2));

    let client = awc::ClientBuilder::new()
        .timeout(Duration::from_secs(600))
        .connector(connector)
        .finish();
    
    // Build the request to pass through
    let mut forwarded_req = client
        .request(req.method().clone(), forwarded_url)
        .no_decompress();
    
    // Copy original headers, excluding ones that would cause issues
    for (header_name, header_value) in req.headers().iter().filter(|(h, _)| 
        *h != header::HOST && 
        *h != header::CONNECTION && 
        *h != header::CONTENT_LENGTH &&
        *h != header::COOKIE &&
        // Strip any client-supplied identity headers to prevent spoofing
        h.as_str().eq_ignore_ascii_case("X-Forwarded-User") == false &&
        h.as_str().eq_ignore_ascii_case("X-Forwarded-Email") == false &&
        h.as_str().eq_ignore_ascii_case("X-Runegate-Authenticated") == false &&
        h.as_str().eq_ignore_ascii_case("X-Runegate-User") == false
    ) {
        forwarded_req = forwarded_req.insert_header((header_name.clone(), header_value.clone()));
    }

    // Sanitize Cookie header: remove Runegate's own session cookie before forwarding
    if let Some(cookie_val) = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        let filtered = cookie_val
            .split(';')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let name = parts.next()?.trim();
                let val = parts.next().unwrap_or("");
                if !name.eq_ignore_ascii_case(&session_cookie_name) {
                    Some(format!("{}={}", name, val))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        if !filtered.is_empty() {
            forwarded_req = forwarded_req.insert_header((header::COOKIE, filtered));
        }
    }
    // Ensure upstream sees the public host so it generates absolute URLs correctly
    // Prefer Host from the original request, falling back to connection_info host
    if let Some(host_val) = req.headers().get(header::HOST).cloned() {
        forwarded_req = forwarded_req.insert_header((header::HOST, host_val));
    } else {
        let host = req.connection_info().host().to_string();
        forwarded_req = forwarded_req.insert_header((header::HOST, host));
    }

    // Ensure X-Forwarded-Proto reflects the external scheme (typically https behind nginx)
    if let Some(xfp) = req.headers().get("X-Forwarded-Proto").cloned() {
        forwarded_req = forwarded_req.insert_header(("X-Forwarded-Proto", xfp));
    }

    // Forward the original client IP if available
    if let Some(client_ip) = req.connection_info().realip_remote_addr() {
        forwarded_req = forwarded_req.insert_header((header::FORWARDED, format!("for={}", client_ip)));
    }
    
    // Inject identity headers while building the request
    if identity_headers_enabled {
        if let Some(email) = identity_email {
            forwarded_req = forwarded_req.insert_header(("X-Runegate-Authenticated", "true"));
            forwarded_req = forwarded_req.insert_header(("X-Runegate-User", email.clone()));
            forwarded_req = forwarded_req.insert_header(("X-Forwarded-User", email.clone()));
            forwarded_req = forwarded_req.insert_header(("X-Forwarded-Email", email));
        } else {
            forwarded_req = forwarded_req.insert_header(("X-Runegate-Authenticated", "false"));
        }
    }

    // For methods that typically have a body, stream it to the upstream.
    // For GET/HEAD/OPTIONS/DELETE, avoid attaching a (possibly empty) body stream
    // to prevent some upstreams from hanging while waiting for a body that never comes.
    let forwarded_req = match *req.method() {
        Method::POST | Method::PUT | Method::PATCH => {
            forwarded_req.send_stream(payload)
        }
        _ => {
            forwarded_req.send()
        }
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
    // Feature flag: stream upstream responses to client without buffering.
    // Enables long-lived endpoints (heartbeat, progress, large downloads) to behave smoothly.
    // Default ON: stream responses unless explicitly disabled
    let stream_responses = match std::env::var("RUNEGATE_STREAM_RESPONSES") {
        Ok(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => false,
        _ => true,
    };

    if stream_responses {
        let stream = forwarded_res.map_err(|e| {
            error!(error = %e, "Upstream body stream error");
            actix_web::error::ErrorBadGateway(e)
        });
        Ok(client_res.streaming(stream))
    } else {
        // Buffer body (default behavior)
        let body = forwarded_res.body().await.map_err(|e| {
            error!(error = %e, "Failed to read response body from target service");
            actix_web::error::ErrorBadGateway(e)
        })?;
        Ok(client_res.body(body))
    }
}

/// Gets the target service URL from environment or uses default
#[instrument]
fn get_target_service_url() -> String {
    std::env::var(TARGET_SERVICE_ENV).unwrap_or_else(|_| DEFAULT_TARGET_SERVICE.to_string())
}
