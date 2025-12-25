use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Pagination parameters
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[allow(unused)]
    pub page: Option<u32>,
    #[allow(unused)]
    pub limit: Option<u32>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(20),
        }
    }
}

impl PaginationParams {
    #[allow(dead_code)]
    pub fn offset(&self) -> i64 {
        let page = self.page.unwrap_or(1).saturating_sub(1);
        let limit = self.limit.unwrap_or(20);
        (page as i64) * (limit as i64)
    }

    #[allow(dead_code)]
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(20) as i64
    }
}

/// Paginated response wrapper
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub total_pages: u32,
}

/// Query parameters for filtering
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub filter: Option<HashMap<String, String>>,
}

/// Sorting direction
#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
pub enum SortOrder {
    #[serde(rename = "asc")]
    Asc,
    #[serde(rename = "desc")]
    #[default]
    Desc,
}

/// Date range filter
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct DateRange {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

/// Sanitize string input
#[allow(dead_code)]
pub fn sanitize_string(input: &str) -> String {
    input.trim().to_string()
}

/// Mask sensitive values partially (e.g., tokens, emails, passwords)
pub fn mask_sensitive(value: &str) -> String {
    if value.is_empty() {
        return "".to_string();
    }

    // If it looks like an email, mask local part
    if let Some(idx) = value.find('@') {
        let (local, domain) = value.split_at(idx);
        let domain = &domain[1..];
        let visible = if local.len() <= 2 { 1 } else { 2 };
        let mut out = String::new();
        out.push_str(&local[..visible.min(local.len())]);
        out.push_str("***");
        out.push('@');
        out.push_str(domain);
        return out;
    }

    // For short strings, show only first character
    if value.len() <= 4 {
        return format!("{}***", &value[..1]);
    }

    // Otherwise show first 4 and last 4 characters
    let start = &value[..4];
    let end = &value[value.len().saturating_sub(4)..];
    format!("{}***{}", start, end)
}

/// Truncate string to maximum length
#[allow(dead_code)]
pub fn truncate_string(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        input.to_string()
    } else {
        format!("{}...", &input[..max_len.saturating_sub(3)])
    }
}

/// Generate secure random string
#[allow(dead_code)]
pub fn generate_random_string(length: usize) -> String {
    // no external rand crate used here; we rely on `getrandom` for secure bytes
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // Use `getrandom` to fill a buffer with cryptographically secure random bytes
    let mut buf = vec![0u8; length];
    getrandom::getrandom(&mut buf).expect("OS RNG failure");

    let mut out = String::with_capacity(length);
    for b in buf {
        let idx = (b as usize) % CHARSET.len();
        out.push(CHARSET[idx] as char);
    }
    out
}

/// Hash string using SHA-256
#[allow(dead_code)]
pub fn hash_string(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Check if email is valid format
#[allow(dead_code)]
pub fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.contains('.') && email.len() <= 254
}

/// Check password strength
#[allow(dead_code)]
pub fn check_password_strength(password: &str) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("Password must be at least 8 characters long".to_string());
    }

    if password.len() > 128 {
        errors.push("Password must be less than 128 characters long".to_string());
    }

    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_upper {
        errors.push("Password must contain at least one uppercase letter".to_string());
    }

    if !has_lower {
        errors.push("Password must contain at least one lowercase letter".to_string());
    }

    if !has_digit {
        errors.push("Password must contain at least one digit".to_string());
    }

    if !has_special {
        errors.push("Password must contain at least one special character".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validation function for the validator crate
pub fn validate_password(password: &str) -> Result<(), validator::ValidationError> {
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());

    if password.len() < 8 || !has_upper || !has_lower || !has_digit {
        return Err(validator::ValidationError::new("password_too_weak"));
    }
    Ok(())
}

/// Format timestamp for display
#[allow(dead_code)]
pub fn format_timestamp(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Calculate time difference in human readable format
#[allow(dead_code)]
pub fn time_ago(dt: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(*dt);

    if duration.num_seconds() < 60 {
        format!("{} seconds ago", duration.num_seconds())
    } else if duration.num_minutes() < 60 {
        format!("{} minutes ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{} hours ago", duration.num_hours())
    } else if duration.num_days() < 30 {
        format!("{} days ago", duration.num_days())
    } else if duration.num_days() < 365 {
        format!("{} months ago", duration.num_days() / 30)
    } else {
        format!("{} years ago", duration.num_days() / 365)
    }
}

/// ID validation
#[allow(dead_code)]
pub fn validate_uuid(id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(id).map_err(|_| "Invalid UUID format".to_string())
}

/// Environment variable helpers
#[allow(dead_code)]
pub mod env {
    use std::env;

    pub fn get_string(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    pub fn get_bool(key: &str, default: bool) -> bool {
        env::var(key)
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(default)
    }

    pub fn get_u32(key: &str, default: u32) -> u32 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_u64(key: &str, default: u64) -> u64 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_usize(key: &str, default: usize) -> usize {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}

/// Logging helpers
#[allow(dead_code)]
pub mod logging {
    use log::{Level, LevelFilter};

    pub fn level_from_string(level: &str) -> LevelFilter {
        match level.to_lowercase().as_str() {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        }
    }

    pub fn log_request(
        method: &str,
        path: &str,
        status: u16,
        duration_ms: u128,
        remote_addr: &str,
    ) {
        let level = match status {
            200..=299 => Level::Info,
            300..=399 => Level::Info,
            400..=499 => Level::Warn,
            500..=599 => Level::Error,
            _ => Level::Info,
        };

        log::log!(
            level,
            "{} {} {} {}ms from {}",
            method,
            path,
            status,
            duration_ms,
            remote_addr
        );
    }
}

/// Error handling utilities
#[allow(dead_code)]
pub mod error {
    use std::fmt;

    #[derive(Debug)]
    pub struct AppError {
        pub message: String,
        pub status_code: u16,
    }

    impl AppError {
        pub fn new(message: &str, status_code: u16) -> Self {
            Self {
                message: message.to_string(),
                status_code,
            }
        }

        pub fn bad_request(message: &str) -> Self {
            Self::new(message, 400)
        }

        pub fn unauthorized(message: &str) -> Self {
            Self::new(message, 401)
        }

        pub fn forbidden(message: &str) -> Self {
            Self::new(message, 403)
        }

        pub fn not_found(message: &str) -> Self {
            Self::new(message, 404)
        }

        pub fn conflict(message: &str) -> Self {
            Self::new(message, 409)
        }

        pub fn internal_server_error(message: &str) -> Self {
            Self::new(message, 500)
        }
    }

    impl fmt::Display for AppError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for AppError {}
}

/// Response helpers
#[allow(dead_code)]
pub mod response {
    use actix_web::HttpResponse;
    use serde::Serialize;

    pub fn json_response<T: Serialize>(data: T, status: u16) -> HttpResponse {
        match actix_web::http::StatusCode::from_u16(status) {
            Ok(code) => HttpResponse::build(code)
                .content_type("application/json")
                .json(data),
            Err(_) => HttpResponse::build(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
                .content_type("application/json")
                .json(serde_json::json!({"error": "Invalid status code"})),
        }
    }

    pub fn success_response<T: Serialize>(data: T) -> HttpResponse {
        json_response(data, 200)
    }

    pub fn error_response(message: &str, status: u16) -> HttpResponse {
        json_response(serde_json::json!({"error": message}), status)
    }

    pub fn validation_error_response(errors: Vec<String>) -> HttpResponse {
        json_response(serde_json::json!({"errors": errors}), 400)
    }
}

use std::sync::Arc;

/// Log internal error details to database and to logger, return the inserted error ID.
pub async fn log_internal_error(
    db: Arc<crate::database::DatabaseService>,
    severity: &str,
    category: &str,
    message: &str,
    details: Option<serde_json::Value>,
    request_id: Option<&str>,
    user_id: Option<uuid::Uuid>,
) -> Result<uuid::Uuid, Box<dyn std::error::Error + Send + Sync>> {
    // Sanitize details before logging to avoid leaking sensitive info
    let sanitized_details = details.map(|d| {
        match d {
            serde_json::Value::Object(mut map) => {
                // iterate keys and mask commonly sensitive fields
                for key in [
                    "password",
                    "token",
                    "access_token",
                    "refresh_token",
                    "authorization",
                    "auth",
                    "email",
                ]
                .iter()
                {
                    if let Some(v) = map.get_mut(*key) {
                        if let Some(s) = v.as_str() {
                            *v = serde_json::Value::String(mask_sensitive(s));
                        }
                    }
                }
                Some(serde_json::Value::Object(map))
            }
            // For arrays or strings, attempt a safe redact by converting to string and masking
            other => {
                let s = other.to_string();
                Some(serde_json::Value::String(truncate_string(
                    &mask_sensitive(&s),
                    1024,
                )))
            }
        }
    });

    // Log sanitized details to stdout/file logger
    log::error!(
        "[{}] {}: {} - details: {:?} request_id: {:?} user_id: {:?}",
        severity,
        category,
        message,
        sanitized_details,
        request_id,
        user_id
    );

    // Insert into database error_logs using sanitized details
    let id = db
        .insert_error_log(
            severity,
            category,
            message,
            sanitized_details.flatten(),
            request_id,
            user_id,
        )
        .await?;
    Ok(id)
}
