use std::sync::Arc;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::auth::AuthService;
use crate::database::DatabaseService;
use crate::models::{ApiResponse, User, LoginRequest, RegisterRequest, Session, AuthResponse};

/// User service for business logic
pub struct UserService {
    pub db: Arc<DatabaseService>,
    pub auth: Arc<AuthService>,
}

impl UserService {
    pub fn new(db: Arc<DatabaseService>, auth: Arc<AuthService>) -> Self {
        Self { db, auth }
    }

    /// Register a new user
    pub async fn register_user(&self, req: RegisterRequest) -> Result<ApiResponse<AuthResponse>, Box<dyn std::error::Error + Send + Sync>> {
        // Validate input
        self.validate_registration_request(&req)?;

        // Check if user already exists
        if self.db.get_user_by_email(&req.email).await.is_ok() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("User with this email already exists"))));
        }

        // Hash password
        let password_hash = self.auth.hash_password(&req.password)?;

        // Create user
        let user = self.db.create_user(&req.email, &req.username, &password_hash).await?;

        // Generate tokens
        let tokens = self.auth.generate_tokens(&user)?;

        // Create session
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: "".to_string(),
            refresh_token_hash: Some("".to_string()),
            ip_address: "".to_string(),
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(24), // 24 hours
            refresh_expires_at: Some(Utc::now() + Duration::hours(24 * 7)), // 7 days
            is_active: true,
            created_at: Utc::now(),
        };

        self.db.create_session(&session).await?;

        Ok(ApiResponse::success(tokens))
    }

    /// Authenticate user
    pub async fn login_user(&self, req: LoginRequest) -> Result<ApiResponse<AuthResponse>, Box<dyn std::error::Error + Send + Sync>> {
        // Validate input
        self.validate_login_request(&req)?;

        // Get user by email
        let user = self.db.get_user_by_email(&req.email).await?;

        // Check if user exists
        let user = match user {
            Some(u) => u,
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid email or password")))),
        };

        // Verify password
        if !self.auth.verify_password(&req.password, &user.password_hash)? {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid email or password"))));
        }

        // Check if user is active
        if !user.is_active {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Account is deactivated"))));
        }

        // Generate tokens
        let tokens = self.auth.generate_tokens(&user)?;

        // Create session
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: "".to_string(),
            refresh_token_hash: Some("".to_string()),
            ip_address: "".to_string(),
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(24),
            refresh_expires_at: Some(Utc::now() + Duration::hours(24 * 7)),
            is_active: true,
            created_at: Utc::now(),
        };

        self.db.create_session(&session).await?;

        Ok(ApiResponse::success(tokens))
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<ApiResponse<AuthResponse>, Box<dyn std::error::Error + Send + Sync>> {
        // Validate refresh token
        let claims = self.auth.validate_refresh_token(refresh_token)?;

        // Get user
        let user_id = Uuid::parse_str(&claims.sub)?;
        let user = self.db.get_user_by_id(&user_id).await?;

        // Check if user exists
        let user = match user {
            Some(u) => u,
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("User not found")))),
        };

        // Check if user is active
        if !user.is_active {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Account is deactivated"))));
        }

        // Invalidate old session
        self.db.invalidate_session_by_refresh_token_hash(&self.auth.hash_token(refresh_token)?).await?;

        // Generate new tokens
        let tokens = self.auth.generate_tokens(&user)?;

        // Create new session
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: "".to_string(),
            refresh_token_hash: Some("".to_string()),
            ip_address: "".to_string(),
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(24),
            refresh_expires_at: Some(Utc::now() + Duration::hours(24 * 7)),
            is_active: true,
            created_at: Utc::now(),
        };

        self.db.create_session(&session).await?;

        Ok(ApiResponse::success(tokens))
    }

    /// Logout user (invalidate session)
    pub async fn logout_user(&self, access_token: &str) -> Result<ApiResponse<String>, Box<dyn std::error::Error + Send + Sync>> {
        // Hash the token to find the session
        let token_hash = self.auth.hash_token(access_token)?;

        // Invalidate session
        self.db.invalidate_session_by_token_hash(&token_hash).await?;

        Ok(ApiResponse::success("Logged out successfully".to_string()))
    }

    /// Get user profile
    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<ApiResponse<User>, Box<dyn std::error::Error + Send + Sync>> {
        let user = self.db.get_user_by_id(&user_id).await?;
        match user {
            Some(u) => Ok(ApiResponse::success(u)),
            None => Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, format!("User not found")))),
        }
    }

    /// Update user profile
    pub async fn update_user_profile(&self, user_id: Uuid, username: Option<String>, email: Option<String>) -> Result<ApiResponse<User>, Box<dyn std::error::Error + Send + Sync>> {
        // Validate input
        if let Some(ref email) = email {
            self.validate_email(email)?;
        }
        if let Some(ref username) = username {
            self.validate_username(username)?;
        }

        // Get current user
        let mut user = match self.db.get_user_by_id(&user_id).await? {
            Some(u) => u,
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, format!("User not found")))),
        };

        // Update fields
        if let Some(username) = username {
            user.username = username;
        }
        if let Some(email) = email {
            user.email = email;
        }
        user.updated_at = Utc::now();

        // Save to database
        self.db.update_user(&user).await?;

        Ok(ApiResponse::success(user))
    }

    /// Deactivate user account
    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<ApiResponse<String>, Box<dyn std::error::Error + Send + Sync>> {
        // Deactivate user
        self.db.deactivate_user(user_id).await?;

        // Invalidate all sessions
        self.db.invalidate_all_user_sessions(user_id).await?;

        Ok(ApiResponse::success("Account deactivated successfully".to_string()))
    }

    /// Get user sessions
    #[allow(dead_code)]
    pub async fn get_user_sessions(&self, user_id: Uuid) -> Result<ApiResponse<Vec<Session>>, Box<dyn std::error::Error + Send + Sync>> {
        let sessions = self.db.get_user_sessions(&user_id).await?;
        Ok(ApiResponse::success(sessions))
    }

    /// Invalidate specific session
    pub async fn invalidate_session(&self, user_id: Uuid, _session_id: Uuid) -> Result<ApiResponse<String>, Box<dyn std::error::Error + Send + Sync>> {
        // For now, we'll invalidate all sessions for the user
        // In a real implementation, you'd get the session by ID and invalidate it specifically
        self.db.invalidate_user_sessions(&user_id).await?;
        Ok(ApiResponse::success("Session invalidated successfully".to_string()))
    }

    /// Validate registration request
    fn validate_registration_request(&self, req: &RegisterRequest) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.validate_email(&req.email)?;
        self.validate_username(&req.username)?;
        self.validate_password(&req.password)?;
        Ok(())
    }

    /// Validate login request
    fn validate_login_request(&self, req: &LoginRequest) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.validate_email(&req.email)?;
        if req.password.is_empty() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Password is required"))));
        }
        Ok(())
    }

    /// Validate email format
    fn validate_email(&self, email: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if email.is_empty() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Email is required"))));
        }
        if !email.contains('@') || !email.contains('.') {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid email format"))));
        }
        if email.len() > 254 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Email too long"))));
        }
        Ok(())
    }

    /// Validate username
    fn validate_username(&self, username: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if username.is_empty() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Username is required"))));
        }
        if username.len() < 3 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Username must be at least 3 characters"))));
        }
        if username.len() > 50 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Username too long"))));
        }
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Username contains invalid characters"))));
        }
        Ok(())
    }

    /// Validate password strength
    fn validate_password(&self, password: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if password.len() < 8 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Password must be at least 8 characters"))));
        }
        if password.len() > 128 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Password too long"))));
        }
        // Check for at least one uppercase, one lowercase, one digit
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());

        if !has_upper || !has_lower || !has_digit {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Password must contain at least one uppercase letter, one lowercase letter, and one digit"))));
        }
        Ok(())
    }
}

/// Session service for session management
pub struct SessionService {
    pub db: Arc<DatabaseService>,
}

impl SessionService {
    pub fn new(db: Arc<DatabaseService>) -> Self {
        Self { db }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db.cleanup_expired_sessions().await?;
        Ok(())
    }

    /// Get active session count for user
    pub async fn get_active_session_count(&self, user_id: Uuid) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
        self.db.get_active_session_count(&user_id).await
    }

    /// Get user sessions
    pub async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Box<dyn std::error::Error + Send + Sync>> {
        self.db.get_user_sessions(&user_id).await
    }

    /// Invalidate all sessions for a user except the current one
    pub async fn invalidate_other_sessions(&self, user_id: Uuid, current_session_id: Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db.invalidate_other_sessions(&user_id, &current_session_id).await
    }
}