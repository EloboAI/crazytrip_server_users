use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// User model with security considerations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub is_active: bool,
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UserRole {
    Admin,
    User,
    Moderator,
}

/// Business account verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessVerificationStatus {
    Pending,
    UnderReview,
    Approved,
    Rejected,
    Suspended,
}

/// Business member role with hierarchical permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BusinessRole {
    Owner,  // Full control including ownership transfer
    Admin,  // Management except ownership
    Member, // Read-only access
}

impl BusinessRole {
    pub fn can_manage_team(&self) -> bool {
        matches!(self, BusinessRole::Owner | BusinessRole::Admin)
    }

    pub fn can_edit_business(&self) -> bool {
        matches!(self, BusinessRole::Owner | BusinessRole::Admin)
    }

    pub fn can_transfer_ownership(&self) -> bool {
        matches!(self, BusinessRole::Owner)
    }
}

/// Business account model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessAccount {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub address: String,
    pub description: Option<String>,
    pub phone: Option<String>,
    pub website: Option<String>,
    pub verification_status: BusinessVerificationStatus,
    pub tax_id: Option<String>,
    pub document_urls: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
}

/// Business member model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessMember {
    pub id: Uuid,
    pub business_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub username: String,
    pub role: BusinessRole,
    pub invited_at: DateTime<Utc>,
    pub joined_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub invited_by: Option<Uuid>,
}

/// Business registration request
#[derive(Debug, Deserialize, Validate)]
pub struct BusinessRegistrationRequest {
    #[validate(length(min = 3, max = 200, message = "Business name must be 3-200 characters"))]
    pub name: String,
    
    #[validate(length(min = 2, max = 100, message = "Category must be 2-100 characters"))]
    pub category: String,
    
    #[validate(length(min = 5, max = 500, message = "Address must be 5-500 characters"))]
    pub address: String,
    
    pub description: Option<String>,
    pub phone: Option<String>,
    pub website: Option<String>,
    pub tax_id: Option<String>,
    pub document_urls: Vec<String>,
    pub is_multi_user_team: bool,
}

/// Business invitation request
#[derive(Debug, Deserialize, Validate)]
pub struct BusinessInvitationRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    
    pub role: BusinessRole,
    pub message: Option<String>,
}

/// Audit log action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditActionType {
    BusinessCreated,
    BusinessUpdated,
    BusinessVerified,
    BusinessRejected,
    MemberInvited,
    MemberJoined,
    MemberRemoved,
    RoleChanged,
    OwnershipTransferred,
    PromotionCreated,
    PromotionUpdated,
    PromotionDeleted,
}

/// Audit log entry model for compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub business_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub action: AuditActionType,
    pub metadata: Option<serde_json::Value>,
    pub target_user_id: Option<Uuid>,
    pub target_username: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Business response (without sensitive info)
#[derive(Debug, Serialize)]
pub struct BusinessResponse {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub address: String,
    pub description: Option<String>,
    pub phone: Option<String>,
    pub website: Option<String>,
    pub verification_status: BusinessVerificationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Business member response
#[derive(Debug, Serialize)]
pub struct BusinessMemberResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub username: String,
    pub role: BusinessRole,
    pub invited_at: DateTime<Utc>,
    pub joined_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Session model for JWT tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub refresh_token_hash: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Login request payload
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Register request payload
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// User data for responses (without sensitive info)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: UserRole,
    pub is_active: bool,
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> ApiResponse<T> {
        ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
            request_id: Uuid::new_v4().to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn error(message: String, request_id: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            timestamp: Utc::now(),
            request_id,
        }
    }
}

/// Health check response
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime_seconds: u64,
    pub database: DatabaseHealth,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub connections_active: u32,
    pub connections_idle: u32,
}

/// Validation errors
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    #[allow(dead_code)]
    pub fn new(field: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ValidationErrors {
    pub errors: Vec<ValidationError>,
}

/// Pagination parameters
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
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

/// Paginated response
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
