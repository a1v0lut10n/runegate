// SPDX-License-Identifier: Apache-2.0
use actix_session::SessionExt;
use actix_web::body::EitherBody;
use actix_web::{
    Error, HttpResponse,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
};
use futures::future::{LocalBoxFuture, Ready, ok};
use std::rc::Rc;
use std::task::{Context, Poll};
use tracing::{debug, instrument, warn};

pub struct AuthMiddleware;

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthMiddleware {
    pub fn new() -> Self {
        AuthMiddleware
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    #[instrument(name = "auth_middleware", skip(self, req), fields(path = %req.path(), method = %req.method()))]
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_owned();
        let service = Rc::clone(&self.service);

        // Skip auth check for public endpoints
        if path == "/login"
            || path == "/health"
            || path == "/rate_limit_info"
            || path == "/login.html"
            || path == "/debug/session"
            || path == "/debug/cookies"
            || path.starts_with("/auth")
            || path.starts_with("/mfa")
            || path.starts_with("/static")
            || path.starts_with("/img")
        {
            debug!("Allowing access to public endpoint: {}", path);
            let fut = service.call(req);

            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Get session from request extensions
        let session = req.get_session();
        debug!("Checking session for path: {}", path);

        // Debug session status
        match session.status() {
            actix_session::SessionStatus::Changed => debug!("Session status: Changed"),
            actix_session::SessionStatus::Purged => debug!("Session status: Purged"),
            actix_session::SessionStatus::Renewed => debug!("Session status: Renewed"),
            actix_session::SessionStatus::Unchanged => debug!("Session status: Unchanged"),
        }

        // Check all session entries
        debug!("Session entries: {:?}", session.entries());

        // Check if user is authenticated
        let authenticated_result = session.get::<bool>("authenticated");
        debug!("Session authenticated result: {:?}", authenticated_result);

        // Also check if email exists in session
        let email_result = session.get::<String>("email");
        debug!("Session email result: {:?}", email_result);

        let authenticated = authenticated_result
            .map(|result| result.unwrap_or(false))
            .unwrap_or(false);

        let preauth_id_exists = session
            .get::<String>("preauth_id")
            .unwrap_or(None)
            .is_some();

        debug!(
            "Final authenticated value: {}, preauth_id_exists: {}",
            authenticated, preauth_id_exists
        );

        if authenticated {
            debug!("User is fully authenticated, allowing access to: {}", path);
            let fut = service.call(req);

            Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            })
        } else if preauth_id_exists {
            debug!(
                "User is in PREAUTH state accessing {}, redirecting to /mfa",
                path
            );
            // Return early with a redirect response to MFA
            let (request, _) = req.into_parts();
            let response = HttpResponse::Found()
                .append_header((header::LOCATION, "/mfa"))
                .finish();

            Box::pin(
                async move { Ok(ServiceResponse::new(request, response).map_into_right_body()) },
            )
        } else {
            debug!(
                "Unauthenticated access attempt to {}, redirecting to login",
                path
            );
            // Return early with a redirect response
            let (request, _) = req.into_parts();
            let response = HttpResponse::Found()
                .append_header((header::LOCATION, "/login.html"))
                .finish();

            Box::pin(
                async move { Ok(ServiceResponse::new(request, response).map_into_right_body()) },
            )
        }
    }
}
