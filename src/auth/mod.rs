use actix_web::HttpMessage;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::models::{AuthResponse, Session, User, UserResponse};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // User ID
    pub email: String,
    pub username: String,
    pub role: String,
    pub exp: i64, // Expiration time
    pub iat: i64, // Issued at
    pub iss: String, // Issuer
    pub jti: String, // JWT ID
}

/// Refresh token claims
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String, // User ID
    pub token_id: String, // Unique token identifier
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub jti: String,
}

/// Authentication service
pub struct AuthService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Hash a password using bcrypt
    pub fn hash_password(&self, password: &str) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(password, self.config.bcrypt_cost)
    }

    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, hash)
    }

    /// Generate access and refresh tokens for a user and return AuthResponse
    pub fn generate_tokens(&self, user: &User) -> Result<AuthResponse, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let token_id = Uuid::new_v4().to_string();

        // Access token claims
        let access_claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            username: user.username.clone(),
            role: format!("{:?}", user.role),
            exp: (now + Duration::hours(self.config.jwt_expiration_hours)).timestamp(),
            iat: now.timestamp(),
            iss: "crazytrip-users".to_string(),
            jti: token_id.clone(),
        };

        // Refresh token claims
        let refresh_claims = RefreshClaims {
            sub: user.id.to_string(),
            token_id: token_id.clone(),
            exp: (now + Duration::days(self.config.refresh_token_expiration_days)).timestamp(),
            iat: now.timestamp(),
            iss: "crazytrip-users".to_string(),
            jti: Uuid::new_v4().to_string(),
        };

        let header = Header::new(Algorithm::HS256);

        let access_token = encode(&header, &access_claims, &self.encoding_key)?;
        let refresh_token = encode(&header, &refresh_claims, &self.encoding_key)?;

        let user_response = UserResponse {
            id: user.id,
            email: user.email.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            is_active: user.is_active,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login_at: user.last_login_at,
        };

        Ok(AuthResponse {
            user: user_response,
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt_expiration_hours * 3600, // Convert to seconds
        })
    }

    /// Validate and decode an access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["crazytrip-users"]);
        validation.set_required_spec_claims(&["exp", "sub", "iat"]);

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Validate and decode a refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["crazytrip-users"]);
        validation.set_required_spec_claims(&["exp", "sub", "iat"]);

        let token_data = decode::<RefreshClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Extract user ID from access token
    #[allow(dead_code)]
    pub fn extract_user_id(&self, token: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
        let claims = self.validate_access_token(token)?;
        Ok(Uuid::parse_str(&claims.sub)?)
    }

    /// Check if user is admin
    #[allow(dead_code)]
    pub fn is_admin(&self, token: &str) -> Result<bool, jsonwebtoken::errors::Error> {
        let claims = self.validate_access_token(token)?;
        Ok(claims.role == "Admin")
    }

    /// Hash a token for storage (using SHA-256)
    pub fn hash_token(&self, token: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Generate a secure session
    #[allow(dead_code)]
    pub fn create_session(&self, user: &User, ip_address: &str, user_agent: Option<&str>) -> Session {
        let now = Utc::now();
        let session_id = Uuid::new_v4();

        Session {
            id: session_id,
            user_id: user.id,
            token_hash: "".to_string(), // Will be set when tokens are generated
            refresh_token_hash: None,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.map(|s| s.to_string()),
            expires_at: now + Duration::hours(self.config.jwt_expiration_hours),
            refresh_expires_at: Some(now + Duration::days(self.config.refresh_token_expiration_days)),
            is_active: true,
            created_at: now,
        }
    }
}

/// Authentication middleware result
#[allow(dead_code)]
pub struct AuthResult {
    pub user_id: Uuid,
    pub claims: Claims,
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    if auth_header.starts_with("Bearer ") {
        Some(&auth_header[7..])
    } else {
        None
    }
}

/// Extract token from request headers
pub fn extract_token_from_request(req: &impl HttpMessage) -> Option<String> {
    // Try Authorization header first
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = extract_bearer_token(auth_str) {
                return Some(token.to_string());
            }
        }
    }

    // Try cookie as fallback
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookie string to find access_token
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("access_token=") {
                    return Some(cookie[13..].to_string());
                }
            }
        }
    }

    None
}

/// Rate limiting store (in-memory for now, should be Redis in production)
pub struct RateLimitStore {
    requests: HashMap<String, Vec<i64>>,
}

impl RateLimitStore {
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    pub fn is_allowed(&mut self, key: &str, max_requests: u32, window_seconds: u64) -> bool {
        let now = Utc::now().timestamp();
        let window_start = now - window_seconds as i64;

        let user_requests = self.requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove old requests outside the window
        user_requests.retain(|&timestamp| timestamp > window_start);

        // Check if under limit
        if user_requests.len() >= max_requests as usize {
            return false;
        }

        // Add current request
        user_requests.push(now);
        true
    }

    #[allow(dead_code)]
    pub fn cleanup(&mut self) {
        let now = Utc::now().timestamp();
        let one_hour_ago = now - 3600;

        self.requests.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp > one_hour_ago);
            !timestamps.is_empty()
        });
    }
}