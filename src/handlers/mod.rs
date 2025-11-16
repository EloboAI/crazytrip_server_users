use actix_web::HttpMessage;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AuthService, Claims};
use crate::models::{ApiResponse, LoginRequest, RegisterRequest};
use crate::services::{SessionService, UserService};
use crate::utils;
use chrono::TimeZone;
use validator::Validate;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    Ok(utils::response::success_response(ApiResponse::success(
        "Server is healthy",
    )))
}

/* readiness_check removed per user request */

/// Readiness check endpoint - verifies DB connectivity
pub async fn readiness_check(
    db_service: web::Data<Arc<crate::database::DatabaseService>>,
) -> Result<HttpResponse> {
    // Try to acquire a client and run a simple query
    match db_service.get_client().await {
        Ok(client) => {
            if let Err(e) = client.execute("SELECT 1", &[]).await {
                log::error!("Readiness DB check failed: {}", e);
                return Ok(utils::response::error_response(
                    "Database unreachable",
                    503,
                ));
            }

            let status = serde_json::json!({
                "status": "ready",
                "database": "ok",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            return Ok(utils::response::success_response(ApiResponse::success(
                status,
            )));
        }
        Err(e) => {
            log::error!("Readiness DB client acquire failed: {}", e);
            return Ok(utils::response::error_response("Database unreachable", 503));
        }
    }
}

/// Server status endpoint
pub async fn server_status() -> Result<HttpResponse> {
    let status = serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    Ok(utils::response::success_response(ApiResponse::success(
        status,
    )))
}

/// Register user endpoint
pub async fn register_user(
    http_req: HttpRequest,
    req: web::Json<RegisterRequest>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let r = req.into_inner();
    if let Err(e) = r.validate() {
        let msgs = flatten_validation_errors(e);
        return Ok(utils::response::validation_error_response(msgs));
    }

    // Extract request metadata
    let ip = http_req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let ua = http_req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match user_service.register_user(r, &ip, ua.as_deref()).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // Log internal error to DB and file
            // We don't want to block the response on DB logging; spawn a task
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "register_user",
                    "Internal error during register",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            // Return generic message to client
            Ok(utils::response::error_response(
                "An internal error occurred",
                500,
            ))
        }
    }
}

/// Login user endpoint
pub async fn login_user(
    http_req: HttpRequest,
    req: web::Json<LoginRequest>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let r = req.into_inner();
    if let Err(e) = r.validate() {
        let msgs = flatten_validation_errors(e);
        return Ok(utils::response::validation_error_response(msgs));
    }

    // Extract request metadata
    let ip = http_req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let ua = http_req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match user_service.login_user(r, &ip, ua.as_deref()).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // If it's a credentials issue, don't log as internal
            let err_msg = err.to_string();
            if err_msg.contains("Invalid email or password")
                || err_msg.contains("Account is deactivated")
            {
                let status = if err_msg.contains("password")
                    || err_msg.contains("Invalid email or password")
                {
                    401
                } else {
                    400
                };
                return Ok(utils::response::error_response(&err_msg.as_str(), status));
            }

            // For other errors, log internals and return generic message
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "login_user",
                    "Internal error during login",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "An internal error occurred",
                500,
            ))
        }
    }
}

fn flatten_validation_errors(err: validator::ValidationErrors) -> Vec<String> {
    let mut msgs = Vec::new();
    for (field, errors) in err.field_errors().iter() {
        for e in errors.iter() {
            let message = if let Some(m) = &e.message {
                m.to_string()
            } else {
                format!("{} {}", field, e.code)
            };
            msgs.push(message);
        }
    }
    msgs
}

/// Refresh token endpoint
pub async fn refresh_token(
    http_req: HttpRequest,
    body: web::Json<serde_json::Value>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let refresh_token = match body.get("refresh_token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => {
            return Ok(utils::response::error_response(
                "Refresh token is required",
                400,
            ))
        }
    };

    // Prefer IP/User-Agent extracted from the HttpRequest; fall back to JSON body values if absent
    let ip = http_req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .or_else(|| {
            body.get("ip_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let ua = http_req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            body.get("user_agent")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    match user_service
        .refresh_token(refresh_token, &ip, ua.as_deref())
        .await
    {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // Log internal error details asynchronously
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "refresh_token",
                    "Refresh token exchange failed",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            // Return a generic unauthorized message
            Ok(utils::response::error_response(
                "Invalid or expired refresh token",
                401,
            ))
        }
    }
}

/// Logout user endpoint
pub async fn logout_user(
    req: HttpRequest,
    user_service: web::Data<Arc<UserService>>,
    auth_service: web::Data<Arc<AuthService>>,
    db_service: web::Data<Arc<crate::database::DatabaseService>>,
) -> Result<HttpResponse> {
    let token = match crate::auth::extract_token_from_request(&req) {
        Some(token) => token,
        None => return Ok(utils::response::error_response("No token provided", 401)),
    };

    match user_service.logout_user(&token).await {
        Ok(response) => {
            // Revoke token JTI asynchronously so logout remains fast
            let db_clone: Arc<crate::database::DatabaseService> = Arc::clone(db_service.get_ref());
            let auth_clone: Arc<AuthService> = Arc::clone(auth_service.get_ref());
            let token_clone = token.clone();
            tokio::spawn(async move {
                if let Ok(claims) = auth_clone.validate_access_token(&token_clone) {
                    // Convert exp (seconds) to Option<DateTime<Utc>> using TimeZone API
                    let expires_at = chrono::Utc.timestamp_opt(claims.exp, 0).single();
                    if let Err(e) = db_clone.revoke_token(&claims.jti, expires_at).await {
                        let _ = utils::log_internal_error(
                            Arc::clone(&db_clone),
                            "ERROR",
                            "revoke_token",
                            "Failed to persist revoked token",
                            Some(serde_json::json!({"error": e.to_string()})),
                            None,
                            None,
                        )
                        .await;
                    }
                }
            });

            Ok(utils::response::success_response(response))
        }
        Err(err) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "logout_user",
                    "Failed to logout user",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Could not logout user",
                400,
            ))
        }
    }
}

/// Get user profile endpoint
pub async fn get_user_profile(
    req: HttpRequest,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "get_user_profile",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match user_service.get_user_profile(user_id).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "get_user_profile",
                    "Failed to get user profile",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response("User not found", 404))
        }
    }
}

/// Update user profile endpoint
pub async fn update_user_profile(
    req: HttpRequest,
    update_req: web::Json<serde_json::Value>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let username = update_req
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let email = update_req
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "update_user_profile",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match user_service
        .update_user_profile(user_id, username, email)
        .await
    {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "update_user_profile",
                    "Failed to update user profile",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to update profile",
                400,
            ))
        }
    }
}

/// Deactivate user account endpoint
pub async fn deactivate_user(
    req: HttpRequest,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "deactivate_user",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match user_service.deactivate_user(user_id).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // Log internal error and return generic message
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "deactivate_user",
                    "Failed to deactivate user",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to deactivate account",
                400,
            ))
        }
    }
}

/// Get user sessions endpoint
pub async fn get_user_sessions(
    req: HttpRequest,
    session_service: web::Data<Arc<SessionService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "get_user_sessions",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match session_service.get_user_sessions(user_id).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "get_user_sessions",
                    "Failed to fetch user sessions",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to retrieve sessions",
                500,
            ))
        }
    }
}

/// Invalidate session endpoint
pub async fn invalidate_session(
    req: HttpRequest,
    path: web::Path<String>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let session_id_str = path.into_inner();
    let session_id = match utils::validate_uuid(&session_id_str) {
        Ok(id) => id,
        Err(_) => return Ok(utils::response::error_response("Invalid session ID", 400)),
    };

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "invalidate_session",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match user_service.invalidate_session(user_id, session_id).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "invalidate_session",
                    "Failed to invalidate session",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to invalidate session",
                400,
            ))
        }
    }
}

/// Invalidate all other sessions endpoint
pub async fn invalidate_other_sessions(
    req: HttpRequest,
    session_service: web::Data<Arc<SessionService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    // Get current session ID from request (this would need to be implemented)
    // For now, we'll invalidate all sessions except the current one
    // This is a simplified implementation
    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "invalidate_other_sessions",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match session_service
        .invalidate_other_sessions(user_id, Uuid::nil())
        .await
    {
        Ok(_) => {
            let response = ApiResponse::success("All other sessions invalidated successfully");
            Ok(utils::response::success_response(response))
        }
        Err(err) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "invalidate_other_sessions",
                    "Failed to invalidate other sessions",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to invalidate other sessions",
                500,
            ))
        }
    }
}

/// Get active session count endpoint
pub async fn get_active_session_count(
    req: HttpRequest,
    session_service: web::Data<Arc<SessionService>>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    let user_id = match utils::validate_uuid(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_msg = format!("Invalid user id in token: {}", &claims.sub);
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "WARN",
                    "get_active_session_count",
                    "Invalid UUID in claims.sub",
                    Some(serde_json::json!({"error": err_msg})),
                    None,
                    None,
                )
                .await;
            });
            return Ok(utils::response::error_response("Unauthorized", 401));
        }
    };

    match session_service.get_active_session_count(user_id).await {
        Ok(count) => {
            let response = ApiResponse::success(serde_json::json!({ "active_sessions": count }));
            Ok(utils::response::success_response(response))
        }
        Err(err) => {
            let db_clone = Arc::clone(&session_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(
                    db_clone,
                    "ERROR",
                    "get_active_session_count",
                    "Failed to get active session count",
                    Some(serde_json::json!({"error": err_str})),
                    None,
                    None,
                )
                .await;
            });

            Ok(utils::response::error_response(
                "Failed to get active session count",
                500,
            ))
        }
    }
}

/// Admin endpoint to get all users (requires admin role)
pub async fn get_all_users(
    req: HttpRequest,
    _user_service: web::Data<Arc<UserService>>,
    _pagination: web::Query<utils::PaginationParams>,
) -> Result<HttpResponse> {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    // Check if user is admin (this would need proper role checking)
    // For now, we'll assume only admins can access this endpoint

    // This is a placeholder - in a real implementation, you'd have proper role checking
    // and pagination logic
    Ok(utils::response::error_response(
        "Admin endpoint not fully implemented",
        501,
    ))
}

/// Admin endpoint to deactivate user (requires admin role)
pub async fn admin_deactivate_user(
    req: HttpRequest,
    path: web::Path<String>,
    _user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    // Check if user is admin (placeholder)
    let user_id_str = path.into_inner();
    let user_id = match utils::validate_uuid(&user_id_str) {
        Ok(id) => id,
        Err(_) => return Ok(utils::response::error_response("Invalid user ID", 400)),
    };

    // This is a placeholder - in a real implementation, you'd check admin role
    // and then deactivate the user
    let response = ApiResponse::success(format!(
        "User {} would be deactivated (placeholder)",
        user_id
    ));
    Ok(utils::response::success_response(response))
}

/// Password reset request endpoint
pub async fn request_password_reset(req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let _email = match req.get("email").and_then(|v| v.as_str()) {
        Some(email) => email,
        None => return Ok(utils::response::error_response("Email is required", 400)),
    };

    // This would integrate with an email service to send reset links
    // For now, return success (in production, you'd send an email)
    let response = ApiResponse::success(
        "If an account with that email exists, a password reset link has been sent",
    );
    Ok(utils::response::success_response(response))
}

/// Password reset confirmation endpoint
pub async fn reset_password(req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let _token = match req.get("token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => {
            return Ok(utils::response::error_response(
                "Reset token is required",
                400,
            ))
        }
    };

    let _new_password = match req.get("new_password").and_then(|v| v.as_str()) {
        Some(password) => password,
        None => {
            return Ok(utils::response::error_response(
                "New password is required",
                400,
            ))
        }
    };

    // This would validate the token and update the password
    // For now, return success
    let response = ApiResponse::success("Password reset successfully");
    Ok(utils::response::success_response(response))
}

/// Email verification endpoint
pub async fn verify_email(req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let _token = match req.get("token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => {
            return Ok(utils::response::error_response(
                "Verification token is required",
                400,
            ))
        }
    };

    // This would validate the email verification token
    // For now, return success
    let response = ApiResponse::success("Email verified successfully");
    Ok(utils::response::success_response(response))
}

/// Resend email verification endpoint
pub async fn resend_verification_email(req: HttpRequest) -> Result<HttpResponse> {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    // This would send a new verification email
    // For now, return success
    let response = ApiResponse::success("Verification email sent");
    Ok(utils::response::success_response(response))
}
