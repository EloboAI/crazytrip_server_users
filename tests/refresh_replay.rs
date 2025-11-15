use std::sync::Arc;

use crazytrip_user_service::auth::AuthService;
use crazytrip_user_service::config::AuthConfig;
use crazytrip_user_service::database::DatabaseService;
use crazytrip_user_service::models::{LoginRequest, RegisterRequest};
use crazytrip_user_service::services::UserService;

#[tokio::test]
async fn refresh_token_replay_should_be_prevented() {
    // Skip the test if DATABASE_URL is not set in the environment
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Skipping test: DATABASE_URL not set");
            return;
        }
    };

    // Build a minimal DatabaseConfig using env
    let db_config = crazytrip_user_service::config::DatabaseConfig {
        url: db_url,
        max_connections: 4,
        min_connections: 1,
        connect_timeout_seconds: 10,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 3600,
    };

    let db = DatabaseService::new(&db_config).await.expect("db init");
    // Ensure schema exists
    db.init_schema().await.expect("init schema");

    let db_arc = Arc::new(db);
    let auth_cfg = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        jwt_expiration_hours: 24,
        refresh_token_expiration_days: 7,
        bcrypt_cost: 4,
    };
    let auth = Arc::new(AuthService::new(auth_cfg));

    let user_service = UserService::new(Arc::clone(&db_arc), Arc::clone(&auth));

    // Create a test user
    let register = RegisterRequest {
        email: "integration_test@example.com".to_string(),
        username: "integration_test_user".to_string(),
        password: "TestPass123".to_string(),
    };

    let _ = user_service
        .register_user(register, "127.0.0.1", Some("test-agent"))
        .await
        .expect("register");

    // Simulate login to get a refresh token
    // For simplicity reuse login_user flow
    let login = LoginRequest {
        email: "integration_test@example.com".to_string(),
        password: "TestPass123".to_string(),
    };

    let auth_resp = user_service
        .login_user(login, "127.0.0.1", Some("test-agent"))
        .await
        .expect("login");
    let tokens = auth_resp.data.expect("auth data");
    let refresh = tokens.refresh_token.clone();

    // First refresh should succeed
    let first = user_service
        .refresh_token(&refresh, "127.0.0.1", Some("test-agent"))
        .await;
    assert!(first.is_ok(), "first refresh should succeed");

    // Second refresh with the same token should be rejected
    let second = user_service
        .refresh_token(&refresh, "127.0.0.1", Some("test-agent"))
        .await;
    assert!(
        second.is_err(),
        "second refresh should be rejected as replay"
    );
}
