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
    // Content Security Policy header value (optional)
    pub content_security_policy: Option<String>,
    // HSTS preload and extra directives
    pub hsts_preload: bool,
    pub hsts_max_age_seconds: u64,
    pub hsts_include_subdomains: bool,
    // Referrer policy
    pub referrer_policy: String,
    // Permissions-Policy / Feature-Policy header
    pub permissions_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_path: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        // Helper to parse env var or default and map parse errors
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("PORT must be a valid number: {}", e),
                ))
            })?;

        let workers = env::var("WORKERS")
            .unwrap_or_else(|_| "4".to_string())
            .parse::<usize>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("WORKERS must be a valid number: {}", e),
                ))
            })?;

        let max_connections = env::var("MAX_CONNECTIONS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse::<usize>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("MAX_CONNECTIONS must be a valid number: {}", e),
                ))
            })?;

        let timeout_seconds = env::var("TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TIMEOUT_SECONDS must be a valid number: {}", e),
                ))
            })?;

        let keep_alive_seconds = env::var("KEEP_ALIVE_SECONDS")
            .unwrap_or_else(|_| "75".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("KEEP_ALIVE_SECONDS must be a valid number: {}", e),
                ))
            })?;

        let client_timeout_seconds = env::var("CLIENT_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("CLIENT_TIMEOUT_SECONDS must be a valid number: {}", e),
                ))
            })?;

        let client_shutdown_seconds = env::var("CLIENT_SHUTDOWN_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("CLIENT_SHUTDOWN_SECONDS must be a valid number: {}", e),
                ))
            })?;

        let database_url = env::var("DATABASE_URL").map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DATABASE_URL must be set",
            ))
        })?;

        let db_max_connections = env::var("DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u32>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("DB_MAX_CONNECTIONS must be a valid number: {}", e),
                ))
            })?;

        let db_min_connections = env::var("DB_MIN_CONNECTIONS")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<u32>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("DB_MIN_CONNECTIONS must be a valid number: {}", e),
                ))
            })?;

        let db_connect_timeout = env::var("DB_CONNECT_TIMEOUT")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("DB_CONNECT_TIMEOUT must be a valid number: {}", e),
                ))
            })?;

        let db_idle_timeout = env::var("DB_IDLE_TIMEOUT")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("DB_IDLE_TIMEOUT must be a valid number: {}", e),
                ))
            })?;

        let db_max_lifetime = env::var("DB_MAX_LIFETIME")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("DB_MAX_LIFETIME must be a valid number: {}", e),
                ))
            })?;

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "JWT_SECRET must be set",
            ))
        })?;

        // Validate JWT_SECRET minimum length for security (HS256 requires strong keys)
        if jwt_secret.len() < 32 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "JWT_SECRET must be at least 32 characters for adequate security",
            )));
        }

        let jwt_expiration_hours = env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse::<i64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("JWT_EXPIRATION_HOURS must be a valid number: {}", e),
                ))
            })?;

        let refresh_token_expiration_days = env::var("REFRESH_TOKEN_EXPIRATION_DAYS")
            .unwrap_or_else(|_| "7".to_string())
            .parse::<i64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "REFRESH_TOKEN_EXPIRATION_DAYS must be a valid number: {}",
                        e
                    ),
                ))
            })?;

        let bcrypt_cost = env::var("BCRYPT_COST")
            .unwrap_or_else(|_| "12".to_string())
            .parse::<u32>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("BCRYPT_COST must be a valid number: {}", e),
                ))
            })?;

        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://127.0.0.1:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();

        let rate_limit_requests = env::var("RATE_LIMIT_REQUESTS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u32>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("RATE_LIMIT_REQUESTS must be a valid number: {}", e),
                ))
            })?;

        let rate_limit_window_seconds = env::var("RATE_LIMIT_WINDOW_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("RATE_LIMIT_WINDOW_SECONDS must be a valid number: {}", e),
                ))
            })?;

        let max_request_size_bytes = env::var("MAX_REQUEST_SIZE_BYTES")
            .unwrap_or_else(|_| "10485760".to_string()) // 10MB
            .parse::<usize>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("MAX_REQUEST_SIZE_BYTES must be a valid number: {}", e),
                ))
            })?;

        let allowed_file_types = env::var("ALLOWED_FILE_TYPES")
            .unwrap_or_else(|_| "image/jpeg,image/png,image/webp".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();

        let max_file_size_bytes = env::var("MAX_FILE_SIZE_BYTES")
            .unwrap_or_else(|_| "5242880".to_string()) // 5MB
            .parse::<usize>()
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("MAX_FILE_SIZE_BYTES must be a valid number: {}", e),
                ))
            })?;

        let content_security_policy = env::var("CONTENT_SECURITY_POLICY").ok();
        let hsts_preload = env::var("HSTS_PRELOAD")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";
        let hsts_max_age_seconds = env::var("HSTS_MAX_AGE")
            .unwrap_or_else(|_| "31536000".to_string())
            .parse()
            .unwrap_or(31536000u64);
        let hsts_include_subdomains = env::var("HSTS_INCLUDE_SUBDOMAINS")
            .unwrap_or_else(|_| "true".to_string())
            .to_lowercase()
            == "true";
        let referrer_policy = env::var("REFERRER_POLICY")
            .unwrap_or_else(|_| "strict-origin-when-cross-origin".to_string());
        let permissions_policy = env::var("PERMISSIONS_POLICY").ok();

        let logging_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let logging_format = env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());
        let logging_file_path = env::var("LOG_FILE_PATH").ok();

        Ok(Self {
            server: ServerConfig {
                host,
                port,
                workers,
                max_connections,
                timeout_seconds,
                keep_alive_seconds,
                client_timeout_seconds,
                client_shutdown_seconds,
            },
            database: DatabaseConfig {
                url: database_url,
                max_connections: db_max_connections,
                min_connections: db_min_connections,
                connect_timeout_seconds: db_connect_timeout,
                idle_timeout_seconds: db_idle_timeout,
                max_lifetime_seconds: db_max_lifetime,
            },
            auth: AuthConfig {
                jwt_secret,
                jwt_expiration_hours,
                refresh_token_expiration_days,
                bcrypt_cost,
            },
            security: SecurityConfig {
                cors_allowed_origins,
                rate_limit_requests,
                rate_limit_window_seconds,
                max_request_size_bytes,
                allowed_file_types,
                max_file_size_bytes,
                content_security_policy,
                hsts_preload,
                hsts_max_age_seconds,
                hsts_include_subdomains,
                referrer_policy,
                permissions_policy,
            },
            logging: LoggingConfig {
                level: logging_level,
                format: logging_format,
                file_path: logging_file_path,
            },
        })
    }
}
