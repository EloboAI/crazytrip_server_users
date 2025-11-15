use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_connections: usize,
    pub timeout_seconds: u64,
    // Keep-alive duration in seconds
    pub keep_alive_seconds: u64,
    // Client timeout for reading payload/body in seconds
    pub client_timeout_seconds: u64,
    // Client shutdown timeout in seconds
    pub client_shutdown_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub refresh_token_expiration_days: i64,
    pub bcrypt_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub cors_allowed_origins: Vec<String>,
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u64,
    pub max_request_size_bytes: usize,
    pub allowed_file_types: Vec<String>,
    pub max_file_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_path: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            server: ServerConfig {
                host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .expect("PORT must be a valid number"),
                workers: env::var("WORKERS")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()
                    .expect("WORKERS must be a valid number"),
                max_connections: env::var("MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "1000".to_string())
                    .parse()
                    .expect("MAX_CONNECTIONS must be a valid number"),
                timeout_seconds: env::var("TIMEOUT_SECONDS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .expect("TIMEOUT_SECONDS must be a valid number"),
                keep_alive_seconds: env::var("KEEP_ALIVE_SECONDS")
                    .unwrap_or_else(|_| "75".to_string())
                    .parse()
                    .expect("KEEP_ALIVE_SECONDS must be a valid number"),
                client_timeout_seconds: env::var("CLIENT_TIMEOUT_SECONDS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .expect("CLIENT_TIMEOUT_SECONDS must be a valid number"),
                client_shutdown_seconds: env::var("CLIENT_SHUTDOWN_SECONDS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .expect("CLIENT_SHUTDOWN_SECONDS must be a valid number"),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .expect("DATABASE_URL must be set"),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .expect("DB_MAX_CONNECTIONS must be a valid number"),
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()
                    .expect("DB_MIN_CONNECTIONS must be a valid number"),
                connect_timeout_seconds: env::var("DB_CONNECT_TIMEOUT")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .expect("DB_CONNECT_TIMEOUT must be a valid number"),
                idle_timeout_seconds: env::var("DB_IDLE_TIMEOUT")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()
                    .expect("DB_IDLE_TIMEOUT must be a valid number"),
                max_lifetime_seconds: env::var("DB_MAX_LIFETIME")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .expect("DB_MAX_LIFETIME must be a valid number"),
            },
            auth: AuthConfig {
                jwt_secret: env::var("JWT_SECRET")
                    .expect("JWT_SECRET must be set"),
                jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()
                    .expect("JWT_EXPIRATION_HOURS must be a valid number"),
                refresh_token_expiration_days: env::var("REFRESH_TOKEN_EXPIRATION_DAYS")
                    .unwrap_or_else(|_| "7".to_string())
                    .parse()
                    .expect("REFRESH_TOKEN_EXPIRATION_DAYS must be a valid number"),
                bcrypt_cost: env::var("BCRYPT_COST")
                    .unwrap_or_else(|_| "12".to_string())
                    .parse()
                    .expect("BCRYPT_COST must be a valid number"),
            },
            security: SecurityConfig {
                cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                    .unwrap_or_else(|_| "http://localhost:3000,http://127.0.0.1:3000".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                rate_limit_requests: env::var("RATE_LIMIT_REQUESTS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()
                    .expect("RATE_LIMIT_REQUESTS must be a valid number"),
                rate_limit_window_seconds: env::var("RATE_LIMIT_WINDOW_SECONDS")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .expect("RATE_LIMIT_WINDOW_SECONDS must be a valid number"),
                max_request_size_bytes: env::var("MAX_REQUEST_SIZE_BYTES")
                    .unwrap_or_else(|_| "10485760".to_string()) // 10MB
                    .parse()
                    .expect("MAX_REQUEST_SIZE_BYTES must be a valid number"),
                allowed_file_types: env::var("ALLOWED_FILE_TYPES")
                    .unwrap_or_else(|_| "image/jpeg,image/png,image/webp".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                max_file_size_bytes: env::var("MAX_FILE_SIZE_BYTES")
                    .unwrap_or_else(|_| "5242880".to_string()) // 5MB
                    .parse()
                    .expect("MAX_FILE_SIZE_BYTES must be a valid number"),
            },
            logging: LoggingConfig {
                level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
                format: env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string()),
                file_path: env::var("LOG_FILE_PATH").ok(),
            },
        })
    }
}