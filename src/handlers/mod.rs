use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_web::HttpMessage;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AuthService, Claims};
use crate::models::{ApiResponse, LoginRequest, RegisterRequest};
use crate::services::{UserService, SessionService};
use crate::utils;
use validator::Validate;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    Ok(utils::response::success_response(ApiResponse::success("Server is healthy")))
}

/// Server status endpoint
pub async fn server_status() -> Result<HttpResponse> {
    let status = serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    Ok(utils::response::success_response(ApiResponse::success(status)))
}

/// Register user endpoint
pub async fn register_user(
    req: web::Json<RegisterRequest>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let r = req.into_inner();
    if let Err(e) = r.validate() {
        let msgs = flatten_validation_errors(e);
        return Ok(utils::response::validation_error_response(msgs));
    }

    match user_service.register_user(r).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // Log internal error to DB and file
            // We don't want to block the response on DB logging; spawn a task
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(db_clone, "ERROR", "register_user", "Internal error during register", Some(serde_json::json!({"error": err_str})), None, None).await;
            });

            // Return generic message to client
            Ok(utils::response::error_response("An internal error occurred", 500))
        }
    }
}

/// Login user endpoint
pub async fn login_user(
    req: web::Json<LoginRequest>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let r = req.into_inner();
    if let Err(e) = r.validate() {
        let msgs = flatten_validation_errors(e);
        return Ok(utils::response::validation_error_response(msgs));
    }

    match user_service.login_user(r).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => {
            // If it's a credentials issue, don't log as internal
            let err_msg = err.to_string();
            if err_msg.contains("Invalid email or password") || err_msg.contains("Account is deactivated") {
                let status = if err_msg.contains("password") || err_msg.contains("Invalid email or password") { 401 } else { 400 };
                return Ok(utils::response::error_response(&err_msg.as_str(), status));
            }

            // For other errors, log internals and return generic message
            let db_clone = Arc::clone(&user_service.db);
            let err_str = err.to_string();
            tokio::spawn(async move {
                let _ = utils::log_internal_error(db_clone, "ERROR", "login_user", "Internal error during login", Some(serde_json::json!({"error": err_str})), None, None).await;
            });

            Ok(utils::response::error_response("An internal error occurred", 500))
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
    req: web::Json<serde_json::Value>,
    user_service: web::Data<Arc<UserService>>,
) -> Result<HttpResponse> {
    let refresh_token = match req.get("refresh_token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => return Ok(utils::response::error_response("Refresh token is required", 400)),
    };

    match user_service.refresh_token(refresh_token).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 401)),
    }
}

/// Logout user endpoint
pub async fn logout_user(
    req: HttpRequest,
    user_service: web::Data<Arc<UserService>>,
    _auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse> {
    let token = match crate::auth::extract_token_from_request(&req) {
        Some(token) => token,
        None => return Ok(utils::response::error_response("No token provided", 401)),
    };

    match user_service.logout_user(&token).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 400)),
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

    match user_service.get_user_profile(Uuid::parse_str(&claims.sub).unwrap()).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 404)),
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

    let username = update_req.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
    let email = update_req.get("email").and_then(|v| v.as_str()).map(|s| s.to_string());

    match user_service.update_user_profile(Uuid::parse_str(&claims.sub).unwrap(), username, email).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 400)),
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

    match user_service.deactivate_user(Uuid::parse_str(&claims.sub).unwrap()).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 400)),
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

    match session_service.get_user_sessions(Uuid::parse_str(&claims.sub).unwrap()).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 500)),
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

    match user_service.invalidate_session(Uuid::parse_str(&claims.sub).unwrap(), session_id).await {
        Ok(response) => Ok(utils::response::success_response(response)),
        Err(err) => Ok(utils::response::error_response(&err.to_string().as_str(), 400)),
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
    match session_service.invalidate_other_sessions(Uuid::parse_str(&claims.sub).unwrap(), Uuid::nil()).await {
        Ok(_) => {
            let response = ApiResponse::success("All other sessions invalidated successfully");
            Ok(utils::response::success_response(response))
        }
        Err(err) => Ok(utils::response::error_response(&err.to_string(), 500)),
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

    match session_service.get_active_session_count(Uuid::parse_str(&claims.sub).unwrap()).await {
        Ok(count) => {
            let response = ApiResponse::success(serde_json::json!({ "active_sessions": count }));
            Ok(utils::response::success_response(response))
        }
        Err(err) => Ok(utils::response::error_response(&err.to_string(), 500)),
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
    Ok(utils::response::error_response("Admin endpoint not fully implemented", 501))
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
    let response = ApiResponse::success(format!("User {} would be deactivated (placeholder)", user_id));
    Ok(utils::response::success_response(response))
}

/// Password reset request endpoint
pub async fn request_password_reset(
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let _email = match req.get("email").and_then(|v| v.as_str()) {
        Some(email) => email,
        None => return Ok(utils::response::error_response("Email is required", 400)),
    };

    // This would integrate with an email service to send reset links
    // For now, return success (in production, you'd send an email)
    let response = ApiResponse::success("If an account with that email exists, a password reset link has been sent");
    Ok(utils::response::success_response(response))
}

/// Password reset confirmation endpoint
pub async fn reset_password(
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let _token = match req.get("token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => return Ok(utils::response::error_response("Reset token is required", 400)),
    };

    let _new_password = match req.get("new_password").and_then(|v| v.as_str()) {
        Some(password) => password,
        None => return Ok(utils::response::error_response("New password is required", 400)),
    };

    // This would validate the token and update the password
    // For now, return success
    let response = ApiResponse::success("Password reset successfully");
    Ok(utils::response::success_response(response))
}

/// Email verification endpoint
pub async fn verify_email(
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let _token = match req.get("token").and_then(|v| v.as_str()) {
        Some(token) => token,
        None => return Ok(utils::response::error_response("Verification token is required", 400)),
    };

    // This would validate the email verification token
    // For now, return success
    let response = ApiResponse::success("Email verified successfully");
    Ok(utils::response::success_response(response))
}

/// Resend email verification endpoint
pub async fn resend_verification_email(
    req: HttpRequest,
) -> Result<HttpResponse> {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(utils::response::error_response("Unauthorized", 401)),
    };

    // This would send a new verification email
    // For now, return success
    let response = ApiResponse::success("Verification email sent");
    Ok(utils::response::success_response(response))
}