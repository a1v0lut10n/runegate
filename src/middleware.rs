use actix_web::{dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, http::header, HttpResponse};
use actix_web::body::EitherBody;
use actix_session::SessionExt;
use futures::future::{ok, LocalBoxFuture, Ready};
use std::task::{Context, Poll};
use tracing::{info, warn, debug, instrument};
use std::rc::Rc;

pub struct AuthMiddleware;

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
            service: Rc::new(service)
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
        if path == "/login" || path == "/health" || path == "/login.html" || path.starts_with("/auth") || path.starts_with("/static") {
            debug!("Allowing access to public endpoint: {}", path);
            let fut = service.call(req);
            
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }
        
        // Get session from request extensions
        let session = req.get_session();
        
        // Check if user is authenticated
        let authenticated = session.get::<bool>("authenticated")
            .map(|result| result.unwrap_or(false))
            .unwrap_or(false);
            
        if authenticated {
            debug!("User is authenticated, allowing access to: {}", path);
            let fut = service.call(req);
            
            Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            })
        } else {
            info!("Unauthenticated access attempt to {}, redirecting to login", path);
            // Return early with a redirect response
            let (request, _) = req.into_parts();
            let response = HttpResponse::Found()
                .append_header((header::LOCATION, "/login.html"))
                .finish();
                
            Box::pin(async move {
                Ok(ServiceResponse::new(request, response).map_into_right_body())
            })
        }
    }
}
