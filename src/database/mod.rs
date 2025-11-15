use chrono::{DateTime, Utc};
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};


use tokio_postgres::NoTls;
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::models::{Session, User, UserRole};

/// Database connection pool
pub type DbPool = Pool;

/// Database service
pub struct DatabaseService {
    pool: DbPool,
}

impl DatabaseService {
    /// Create a new database service with connection pool
    pub async fn new(config: &DatabaseConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut cfg = Config::new();
        cfg.url = Some(config.url.clone());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;

        // Test connection
        let client = pool.get().await?;
        client.execute("SELECT 1", &[]).await?;

        log::info!("Database connection established");

        Ok(Self { pool })
    }

    /// Get a database client from the pool
    pub async fn get_client(&self) -> Result<deadpool_postgres::Client, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.pool.get().await?)
    }

    /// Initialize database schema
    #[allow(dead_code)]
    pub async fn init_schema(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        // Ensure pgcrypto extension for gen_random_uuid() is present
        client.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto", &[]).await.ok();

        // Create users table
        client.execute("\
            CREATE TABLE IF NOT EXISTS users (\
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\
                email VARCHAR(255) UNIQUE NOT NULL,\
                username VARCHAR(50) UNIQUE NOT NULL,\
                password_hash VARCHAR(255) NOT NULL,\
                role VARCHAR(20) NOT NULL DEFAULT 'User',\
                is_active BOOLEAN NOT NULL DEFAULT true,\
                is_email_verified BOOLEAN NOT NULL DEFAULT false,\
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
                last_login_at TIMESTAMPTZ,\
                login_attempts INTEGER NOT NULL DEFAULT 0,\
                locked_until TIMESTAMPTZ,\
                CONSTRAINT valid_role CHECK (role IN ('User', 'Admin', 'Moderator')),\
                CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{2,}$'),\
                CONSTRAINT valid_username CHECK (length(username) >= 3 AND length(username) <= 50)\
            )\
        ", &[]).await?;

        // Create sessions table (indexes created separately)
        client.execute("\
            CREATE TABLE IF NOT EXISTS sessions (\
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,\
                token_hash VARCHAR(255) UNIQUE NOT NULL,\
                refresh_token_hash VARCHAR(255) UNIQUE,\
                ip_address INET NOT NULL,\
                user_agent VARCHAR(500),\
                expires_at TIMESTAMPTZ NOT NULL,\
                refresh_expires_at TIMESTAMPTZ,\
                is_active BOOLEAN NOT NULL DEFAULT true,\
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
            )\
        ", &[]).await?;

        // Create indexes for performance
        client.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)", &[]).await?;

        // Create error_logs table for server-side error auditing
        client.execute("\
            CREATE TABLE IF NOT EXISTS error_logs (\
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
                severity VARCHAR(20) NOT NULL,\
                category VARCHAR(100) NOT NULL,\
                message TEXT NOT NULL,\
                details JSONB,\
                request_id VARCHAR(100),\
                user_id UUID NULL\
            )\
        ", &[]).await?;

        client.execute("CREATE INDEX IF NOT EXISTS idx_error_logs_severity ON error_logs(severity)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_error_logs_occurred_at ON error_logs(occurred_at)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_error_logs_category ON error_logs(category)", &[]).await?;

        // Create revoked_tokens table for token revocation (prevent replay attacks)
        client.execute("\
            CREATE TABLE IF NOT EXISTS revoked_tokens (\
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\
                jti VARCHAR(100) UNIQUE NOT NULL,\
                revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
                expires_at TIMESTAMPTZ NULL\
            )\
        ", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(jti)", &[]).await?;
        client.execute("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at)", &[]).await?;

        log::info!("Database schema initialized");
        Ok(())
    }

    /// Revoke a token by JTI and optional expiry time
    pub async fn revoke_token(&self, jti: &str, expires_at: Option<DateTime<Utc>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("\
            INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO UPDATE SET revoked_at = NOW(), expires_at = EXCLUDED.expires_at\
        ", &[&jti, &expires_at]).await?;

        Ok(())
    }

    /// Check if a token JTI is revoked
    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let row = client.query_opt("SELECT jti FROM revoked_tokens WHERE jti = $1 LIMIT 1", &[&jti]).await?;
        Ok(row.is_some())
    }

    /// Insert an error log record
    pub async fn insert_error_log(&self, severity: &str, category: &str, message: &str, details: Option<serde_json::Value>, request_id: Option<&str>, user_id: Option<Uuid>) -> Result<Uuid, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let id = Uuid::new_v4();
        client.execute("\
            INSERT INTO error_logs (id, severity, category, message, details, request_id, user_id)\
            VALUES ($1, $2, $3, $4, $5, $6, $7)\
        ", &[
            &id,
            &severity,
            &category,
            &message,
            &details,
            &request_id,
            &user_id,
        ]).await?;

        Ok(id)
    }

    /// Create a new user
    pub async fn create_user(&self, email: &str, username: &str, password_hash: &str) -> Result<User, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let row = client.query_one("
            INSERT INTO users (email, username, password_hash)
            VALUES ($1, $2, $3)
            RETURNING id, email, username, password_hash, role, is_active, is_email_verified,
                      created_at, updated_at, last_login_at, login_attempts, locked_until
        ", &[&email, &username, &password_hash]).await?;

        Ok(Self::row_to_user(&row))
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let rows = client.query("
            SELECT id, email, username, password_hash, role, is_active, is_email_verified,
                   created_at, updated_at, last_login_at, login_attempts, locked_until
            FROM users WHERE id = $1
        ", &[id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self::row_to_user(&rows[0])))
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let rows = client.query("
            SELECT id, email, username, password_hash, role, is_active, is_email_verified,
                   created_at, updated_at, last_login_at, login_attempts, locked_until
            FROM users WHERE email = $1
        ", &[&email]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self::row_to_user(&rows[0])))
    }

    /// Update user login info
    #[allow(dead_code)]
    pub async fn update_user_login(&self, user_id: &Uuid, _ip_address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE users
            SET last_login_at = NOW(), login_attempts = 0, locked_until = NULL, updated_at = NOW()
            WHERE id = $1
        ", &[user_id]).await?;

        Ok(())
    }

    /// Increment login attempts
    #[allow(dead_code)]
    pub async fn increment_login_attempts(&self, user_id: &Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE users
            SET login_attempts = login_attempts + 1, updated_at = NOW()
            WHERE id = $1
        ", &[user_id]).await?;

        Ok(())
    }

    /// Lock user account
    #[allow(dead_code)]
    pub async fn lock_user_account(&self, user_id: &Uuid, locked_until: DateTime<Utc>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE users
            SET locked_until = $2, updated_at = NOW()
            WHERE id = $1
        ", &[user_id, &locked_until]).await?;

        Ok(())
    }

    /// Create a new session
    pub async fn create_session(&self, session: &Session) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            INSERT INTO sessions (id, user_id, token_hash, refresh_token_hash, ip_address,
                                user_agent, expires_at, refresh_expires_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ", &[
            &session.id,
            &session.user_id,
            &session.token_hash,
            &session.refresh_token_hash,
            &session.ip_address,
            &session.user_agent,
            &session.expires_at,
            &session.refresh_expires_at,
            &session.is_active,
        ]).await?;

        Ok(())
    }

    /// Get session by token hash
    #[allow(dead_code)]
    pub async fn get_session_by_token(&self, token_hash: &str) -> Result<Option<Session>, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let rows = client.query("
            SELECT id, user_id, token_hash, refresh_token_hash, ip_address, user_agent,
                   expires_at, refresh_expires_at, is_active, created_at
            FROM sessions
            WHERE token_hash = $1 AND is_active = true AND expires_at > NOW()
        ", &[&token_hash]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self::row_to_session(&rows[0])))
    }

    /// Invalidate session
    pub async fn invalidate_session(&self, token_hash: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE sessions SET is_active = false WHERE token_hash = $1
        ", &[&token_hash]).await?;

        Ok(())
    }

    /// Invalidate all user sessions
    pub async fn invalidate_user_sessions(&self, user_id: &Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE sessions SET is_active = false WHERE user_id = $1
        ", &[user_id]).await?;

        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let query = "DELETE FROM sessions WHERE expires_at < NOW() RETURNING id";
        match client.query(query, &[]).await {
            Ok(rows) => {
                let removed = rows.len() as u64;
                log::debug!("cleanup_expired_sessions removed {} rows", removed);
                Ok(removed)
            }
            Err(e) => {
                log::error!("cleanup_expired_sessions db error: {}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Get active session count for a user
    pub async fn get_active_session_count(&self, user_id: &Uuid) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let row = client.query_one("
            SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND is_active = true
        ", &[user_id]).await?;

        Ok(row.get(0))
    }

    /// Invalidate all sessions for a user except the current one
    pub async fn invalidate_other_sessions(&self, user_id: &Uuid, current_session_id: &Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE sessions SET is_active = false WHERE user_id = $1 AND id != $2
        ", &[user_id, current_session_id]).await?;

        Ok(())
    }

    /// Invalidate session by refresh token hash
    pub async fn invalidate_session_by_refresh_token_hash(&self, refresh_token_hash: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE sessions SET is_active = false WHERE refresh_token_hash = $1
        ", &[&refresh_token_hash]).await?;

        Ok(())
    }

    /// Invalidate session by access token hash
    pub async fn invalidate_session_by_token_hash(&self, token_hash: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.invalidate_session(token_hash).await
    }

    /// Update user information
    pub async fn update_user(&self, user: &User) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let role_str = match user.role {
            UserRole::Admin => "Admin",
            UserRole::Moderator => "Moderator",
            UserRole::User => "User",
        };

        client.execute("
            UPDATE users
            SET email = $2, username = $3, password_hash = $4, role = $5,
                is_active = $6, is_email_verified = $7, updated_at = $8,
                last_login_at = $9, login_attempts = $10, locked_until = $11
            WHERE id = $1
        ", &[
            &user.id,
            &user.email,
            &user.username,
            &user.password_hash,
            &role_str,
            &user.is_active,
            &user.is_email_verified,
            &user.updated_at,
            &user.last_login_at,
            &user.login_attempts,
            &user.locked_until,
        ]).await?;

        Ok(())
    }

    /// Deactivate user account
    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        client.execute("
            UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1
        ", &[&user_id]).await?;

        Ok(())
    }

    /// Invalidate all sessions for a user
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.invalidate_user_sessions(&user_id).await
    }

    /// Get all sessions for a user
    pub async fn get_user_sessions(&self, user_id: &Uuid) -> Result<Vec<Session>, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.get_client().await?;

        let rows = client.query("
            SELECT id, user_id, token_hash, refresh_token_hash, ip_address, user_agent, expires_at, refresh_expires_at, is_active, created_at
            FROM sessions WHERE user_id = $1 ORDER BY created_at DESC
        ", &[user_id]).await?;

        let sessions = rows.into_iter()
            .map(|row| Self::row_to_session(&row))
            .collect();

        Ok(sessions)
    }

    /// Helper to convert database row to User
    fn row_to_user(row: &tokio_postgres::Row) -> User {
        User {
            id: row.get(0),
            email: row.get(1),
            username: row.get(2),
            password_hash: row.get(3),
            role: match row.get::<_, &str>(4) {
                "Admin" => UserRole::Admin,
                "Moderator" => UserRole::Moderator,
                _ => UserRole::User,
            },
            is_active: row.get(5),
            is_email_verified: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
            last_login_at: row.get(9),
            login_attempts: row.get(10),
            locked_until: row.get(11),
        }
    }

    /// Helper to convert database row to Session
    fn row_to_session(row: &tokio_postgres::Row) -> Session {
        Session {
            id: row.get(0),
            user_id: row.get(1),
            token_hash: row.get(2),
            refresh_token_hash: row.get(3),
            ip_address: row.get(4),
            user_agent: row.get(5),
            expires_at: row.get(6),
            refresh_expires_at: row.get(7),
            is_active: row.get(8),
            created_at: row.get(9),
        }
    }
}