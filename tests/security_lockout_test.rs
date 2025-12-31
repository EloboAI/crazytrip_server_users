#[cfg(test)]
mod tests {
    use crazytrip_user_service::config::{AuthConfig, DatabaseConfig};
    use crazytrip_user_service::database::DatabaseService;
    use crazytrip_user_service::auth::AuthService;
    use crazytrip_user_service::services::UserService;
    use crazytrip_user_service::models::{LoginRequest, RegisterRequest};
    use std::sync::Arc;
    use uuid::Uuid;

    // Helper to setup service (requires running DB)
    async fn setup_service() -> Option<UserService> {
        // Load .env from project root if possible, or expect env vars
        dotenvy::from_filename(".env").ok();
        
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };
        
        let db_config = DatabaseConfig {
            url: db_url,
            max_connections: 10,
            min_connections: 1,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 300,
            max_lifetime_seconds: 3600,
        };
        let db = match DatabaseService::new(&db_config).await {
            Ok(db) => db,
            Err(_) => return None,
        };
        
        let auth_config = AuthConfig {
            jwt_secret: "test_secret_must_be_32_chars_long!!".to_string(),
            jwt_expiration_hours: 1,
            refresh_token_expiration_days: 1,
            bcrypt_cost: 4, // low cost for tests
        };
        let auth = Arc::new(AuthService::new(auth_config)); // Pass by value
        
        Some(UserService::new(Arc::new(db), auth))
    }

    #[tokio::test]
    async fn test_account_lockout_protection() {
        let service = match setup_service().await {
            Some(s) => s,
            None => {
                println!("Skipping test_account_lockout_protection: No DB connection or DATABASE_URL not set");
                return;
            }
        };

        // Create unique user
        let unique_id = Uuid::new_v4();
        let email = format!("lockout_{}@test.com", unique_id);
        let password = "TestPassword123!";
        let username = format!("user_{}", unique_id.simple());
        // Truncate username if too long (simple uuid is 32 chars, fine)

        println!("Testing lockout for {}", email);

        // 1. Register User
        let reg_req = RegisterRequest {
            email: email.clone(),
            username: username,
            password: password.to_string(),
        };
        
        if let Err(e) = service.register_user(reg_req, "127.0.0.1", None).await {
            panic!("Failed to register test user: {}", e);
        }

        // 2. Fail login 5 times
        let bad_req = LoginRequest {
            email: email.clone(),
            password: "WrongPassword123!".to_string(),
        };

        for i in 1..=5 {
            let result = service.login_user(bad_req.clone(), "127.0.0.1", None).await;
            assert!(result.is_err(), "Login attempt {} should fail", i);
            if i < 5 {
                // Verify error is "Invalid email or password", not lockout yet
                let err_msg = result.unwrap_err().to_string();
                assert!(err_msg.contains("Invalid email or password"), "Unexpected error at attempt {}: {}", i, err_msg);
            }
        }

        // 3. 6th attempt should be locked (checks logic: if new_attempts >= 5)
        // Actually, the lockout happens *after* the 5th failure.
        // So the 6th attempt (even with correct password) should fail with Lockout message.
        
        let result = service.login_user(bad_req.clone(), "127.0.0.1", None).await;
        assert!(result.is_err(), "6th attempt should fail");
        let err_msg = result.unwrap_err().to_string();
        
        // Depending on implementation, it might lock *during* the 5th failure processing 
        // and return "Invalid credentials", but subsequent calls return "Locked".
        // Let's check what the service returns.
        // Reading code: 
        // if new_attempts >= 5 { lock_user_account(...) }
        // return Err("Invalid email or password")
        
        // So the 5th failure returns "Invalid...", but locks the account.
        // The 6th attempt should check locked status first.
        
        assert!(err_msg.contains("Account is temporarily locked") || err_msg.contains("Invalid email"), 
                "6th attempt might be invalid or locked. Got: {}", err_msg);

        // 4. Correct password should DEFINITELY fail now
        let good_req = LoginRequest {
            email: email.clone(),
            password: password.to_string(),
        };
        let result = service.login_user(good_req, "127.0.0.1", None).await;
        assert!(result.is_err(), "Should be locked even with correct password");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Account is temporarily locked"), "Error should be lockout. Got: {}", err_msg);
        
        println!("Account lockout Test PASSED");
    }
}
