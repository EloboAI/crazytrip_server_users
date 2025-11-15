use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpMessage, HttpResponse,
};

use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::auth::{AuthService, RateLimitStore, extract_token_from_request};


/// Authentication middleware
pub struct AuthMiddleware {
    pub auth_service: Arc<AuthService>,
    pub db_service: Arc<crate::database::DatabaseService>,
}

impl<S> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Arc::new(service),
            auth_service: Arc::clone(&self.auth_service),
            db_service: Arc::clone(&self.db_service),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Arc<S>,
    auth_service: Arc<AuthService>,
    db_service: Arc<crate::database::DatabaseService>,
}

impl<S> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);
        let auth_service = Arc::clone(&self.auth_service);
        let db_service = Arc::clone(&self.db_service);

        Box::pin(async move {
            // Skip auth for certain public routes
            let path = req.path();
            if path.starts_with("/health") || path.starts_with("/api/v1/status") || path.starts_with("/api/v1/auth") {
                return service.call(req).await;
            }

            // Extract token
            let token = match extract_token_from_request(&req) {
                Some(token) => token,
                None => {
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Missing authentication token"}));
                    return Ok(req.into_response(response));
                }
            };

            // Validate token
            match auth_service.validate_access_token(&token) {
                Ok(claims) => {
                    // Check revocation list by JTI
                    if let Ok(is_revoked) = db_service.is_token_revoked(&claims.jti).await {
                        if is_revoked {
                            let response = HttpResponse::Unauthorized()
                                .json(serde_json::json!({"error": "Token revoked"}));
                            return Ok(req.into_response(response));
                        }
                    }

                    // Add user info to request extensions
                    req.extensions_mut().insert(claims);
                    service.call(req).await
                }
                Err(_) => {
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Invalid or expired token"}));
                    Ok(req.into_response(response))
                }
            }
        })
    }
}

/// CORS middleware
pub struct CorsMiddleware {
    pub allowed_origins: Vec<String>,
}

impl<S> Transform<S, ServiceRequest> for CorsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = CorsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CorsMiddlewareService {
            service: Arc::new(service),
            allowed_origins: self.allowed_origins.clone(),
        }))
    }
}

pub struct CorsMiddlewareService<S> {
    service: Arc<S>,
    allowed_origins: Vec<String>,
}

impl<S> Service<ServiceRequest> for CorsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);
        let allowed_origins = self.allowed_origins.clone();

        Box::pin(async move {
            let mut res = service.call(req).await?;

            // Get origin before borrowing headers mutably
            let origin_header = res.request().headers().get("origin").cloned();

            // Add CORS headers
            let headers = res.headers_mut();

            if let Some(origin) = origin_header {
                if let Ok(origin_str) = origin.to_str() {
                    if allowed_origins.contains(&origin_str.to_string()) || allowed_origins.contains(&"*".to_string()) {
                        headers.insert(
                            header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            origin,
                        );
                    }
                }
            }

            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                header::HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
            );

            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::HeaderValue::from_static("Content-Type, Authorization, X-Requested-With"),
            );

            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                header::HeaderValue::from_static("true"),
            );

            Ok(res)
        })
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    pub store: Arc<Mutex<RateLimitStore>>,
    pub max_requests: u32,
    pub window_seconds: u64,
    pub auth_service: Option<Arc<crate::auth::AuthService>>,
}

impl<S> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddlewareService {
            service: Arc::new(service),
            store: Arc::clone(&self.store),
            max_requests: self.max_requests,
            window_seconds: self.window_seconds,
            auth_service: self.auth_service.clone(),
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: Arc<S>,
    store: Arc<Mutex<RateLimitStore>>,
    max_requests: u32,
    window_seconds: u64,
    auth_service: Option<Arc<crate::auth::AuthService>>,
}

impl<S> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);
        let store = Arc::clone(&self.store);
        let max_requests = self.max_requests;
        let window_seconds = self.window_seconds;
        let auth_service = self.auth_service.clone();

        Box::pin(async move {
            // Get client IP for rate limiting
            let ip = req.connection_info().peer_addr()
                .unwrap_or("unknown")
                .to_string();

            // Try to extract identifying key: prefer user id (from valid token), then api key, then fallback to IP-only
            let mut key_parts: Vec<String> = Vec::new();

            // API key header if present
            if let Some(api_val) = req.headers().get("x-api-key") {
                if let Ok(api_str) = api_val.to_str() {
                    key_parts.push(format!("api:{}", api_str));
                }
            }

            // Bearer token: try to validate to get user id
            if let Some(token) = extract_token_from_request(&req) {
                if let Some(auth) = auth_service.as_ref() {
                    if let Ok(claims) = auth.validate_access_token(&token) {
                        key_parts.push(format!("user:{}", claims.sub));
                    } else {
                        // If token can't be validated, include token prefix to still rate limit
                        let short = &token.as_bytes()[..std::cmp::min(8, token.len())];
                        let hex_str = short.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        key_parts.push(format!("token:{}", hex_str));
                    }
                } else {
                    // no auth service available: use token prefix
                    let short = &token.as_bytes()[..std::cmp::min(8, token.len())];
                    let hex_str = short.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    key_parts.push(format!("token:{}", hex_str));
                }
            }

            // Build final key
            let key = if !key_parts.is_empty() {
                format!("{}|ip:{}", key_parts.join("+"), ip)
            } else {
                ip.clone()
            };

            // Check rate limit
            let mut store = store.lock().await;
            if !store.is_allowed(&key, max_requests, window_seconds) {
                let response = HttpResponse::TooManyRequests()
                    .json(serde_json::json!({"error": "Rate limit exceeded. Please try again later."}));
                return Ok(req.into_response(response));
            }

            service.call(req).await
        })
    }
}

/// Request size limiting middleware
pub struct RequestSizeLimitMiddleware {
    pub max_size: usize,
}

impl<S> Transform<S, ServiceRequest> for RequestSizeLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestSizeLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestSizeLimitMiddlewareService {
            service: Arc::new(service),
            max_size: self.max_size,
        }))
    }
}

pub struct RequestSizeLimitMiddlewareService<S> {
    service: Arc<S>,
    max_size: usize,
}

impl<S> Service<ServiceRequest> for RequestSizeLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);
        let max_size = self.max_size;

        Box::pin(async move {
            // Check Content-Length header
            if let Some(content_length) = req.headers().get("content-length") {
                if let Ok(length_str) = content_length.to_str() {
                    if let Ok(length) = length_str.parse::<usize>() {
                        if length > max_size {
                            let response = HttpResponse::PayloadTooLarge()
                                .json(serde_json::json!({"error": format!("Request size {} exceeds maximum allowed size {}", length, max_size)}));
                            return Ok(req.into_response(response));
                        }
                    }
                }
            }

            service.call(req).await
        })
    }
}

/// Security headers middleware
pub struct SecurityHeadersMiddleware;

impl<S> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

pub struct SecurityHeadersMiddlewareService<S> {
    service: Arc<S>,
}

impl<S> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);

        Box::pin(async move {
            let mut res = service.call(req).await?;

            let headers = res.headers_mut();

            // Security headers
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );

            headers.insert(
                header::X_FRAME_OPTIONS,
                header::HeaderValue::from_static("DENY"),
            );

            headers.insert(
                header::X_XSS_PROTECTION,
                header::HeaderValue::from_static("1; mode=block"),
            );

            headers.insert(
                header::STRICT_TRANSPORT_SECURITY,
                header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );

            headers.insert(
                header::REFERRER_POLICY,
                header::HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            Ok(res)
        })
    }
}

/// Logging middleware
pub struct LoggingMiddleware;

impl<S> Transform<S, ServiceRequest> for LoggingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = LoggingMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(LoggingMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

pub struct LoggingMiddlewareService<S> {
    service: Arc<S>,
}

impl<S> Service<ServiceRequest> for LoggingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Arc::clone(&self.service);
        let start_time = std::time::Instant::now();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let remote_addr = req.connection_info().peer_addr().unwrap_or("unknown").to_string();

        Box::pin(async move {
            let result = service.call(req).await;
            let duration = start_time.elapsed();

            match &result {
                Ok(res) => {
                    log::info!(
                        "Request completed: {} {} {} {}ms from {}",
                        method, uri, res.status().as_u16(), duration.as_millis(), remote_addr
                    );
                }
                Err(err) => {
                    log::error!(
                        "Request failed: {} {} {} {}ms from {}",
                        method, uri, err, duration.as_millis(), remote_addr
                    );
                }
            }

            result
        })
    }
}