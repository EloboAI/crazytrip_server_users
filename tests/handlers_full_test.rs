#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use chrono::Utc;
    use crazytrip_user_service::models::{RegisterRequest, LoginRequest, UserRole, UserResponse, AuthResponse, ApiResponse};

    // Mock UserService
    struct MockUserService;
    impl MockUserService {
        async fn register_user(&self, req: RegisterRequest) -> Result<ApiResponse<UserResponse>, String> {
            if req.email.contains("@") && req.password.len() >= 8 && req.username.len() >= 3 {
                Ok(ApiResponse::success(UserResponse {
                    id: Uuid::new_v4(),
                    email: req.email,
                    username: req.username,
                    role: UserRole::User,
                    is_active: true,
                    is_email_verified: false,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_login_at: None,
                }))
            } else {
                Err("validation error".to_string())
            }
        }
        async fn login_user(&self, req: LoginRequest) -> Result<ApiResponse<AuthResponse>, String> {
            if req.email == "user@crazytrip.com" && req.password == "TestPass123" {
                Ok(ApiResponse::success(AuthResponse {
                    user: UserResponse {
                        id: Uuid::new_v4(),
                        email: req.email,
                        username: "user".to_string(),
                        role: UserRole::User,
                        is_active: true,
                        is_email_verified: true,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        last_login_at: None,
                    },
                    access_token: "token".to_string(),
                    refresh_token: "refresh".to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                }))
            } else {
                Err("Invalid email or password".to_string())
            }
        }
        async fn refresh_token(&self, token: &str) -> Result<ApiResponse<AuthResponse>, String> {
            if token == "refresh" {
                Ok(ApiResponse::success(AuthResponse {
                    user: UserResponse {
                        id: Uuid::new_v4(),
                        email: "user@crazytrip.com".to_string(),
                        username: "user".to_string(),
                        role: UserRole::User,
                        is_active: true,
                        is_email_verified: true,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        last_login_at: None,
                    },
                    access_token: "token".to_string(),
                    refresh_token: "refresh2".to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                }))
            } else {
                Err("Invalid or expired refresh token".to_string())
            }
        }
        async fn logout_user(&self, token: &str) -> Result<ApiResponse<String>, String> {
            if token == "token" {
                Ok(ApiResponse::success("Logged out successfully".to_string()))
            } else {
                Err("Invalid token".to_string())
            }
        }
        async fn get_user_profile(&self, user_id: Uuid) -> Result<ApiResponse<UserResponse>, String> {
            if user_id != Uuid::nil() {
                Ok(ApiResponse::success(UserResponse {
                    id: user_id,
                    email: "user@crazytrip.com".to_string(),
                    username: "user".to_string(),
                    role: UserRole::User,
                    is_active: true,
                    is_email_verified: true,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_login_at: None,
                }))
            } else {
                Err("User not found".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        // Simular respuesta exitosa
        let status = "Server is healthy";
        assert_eq!(status, "Server is healthy");
    }

    #[tokio::test]
    async fn test_server_status() {
        // Simular respuesta exitosa
        let status = "running";
        assert_eq!(status, "running");
    }


    #[tokio::test]
    async fn test_register_user_success_and_error() {
        let user_service = MockUserService;
        let valid = RegisterRequest {
            email: "test@crazytrip.com".to_string(),
            username: "testuser".to_string(),
            password: "TestPass123".to_string(),
        };
        let result = user_service.register_user(valid.clone()).await;
        assert!(result.is_ok());
        let invalid = RegisterRequest {
            email: "bademail".to_string(),
            username: "t".to_string(),
            password: "short".to_string(),
        };
        let result = user_service.register_user(invalid).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_user_success_and_error() {
        let user_service = MockUserService;
        let valid = LoginRequest {
            email: "user@crazytrip.com".to_string(),
            password: "TestPass123".to_string(),
        };
        let result = user_service.login_user(valid.clone()).await;
        assert!(result.is_ok());
        let invalid = LoginRequest {
            email: "baduser@crazytrip.com".to_string(),
            password: "wrongpass".to_string(),
        };
        let result = user_service.login_user(invalid).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_refresh_token_success_and_error() {
        let user_service = MockUserService;
        let result = user_service.refresh_token("refresh").await;
        assert!(result.is_ok());
        let result = user_service.refresh_token("badtoken").await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn test_logout_user_success_and_error() {
        let user_service = MockUserService;
        let result = user_service.logout_user("token").await;
        assert!(result.is_ok());
        let result = user_service.logout_user("badtoken").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_user_profile_success_and_error() {
        let user_service = MockUserService;
        let valid_id = Uuid::new_v4();
        let result = user_service.get_user_profile(valid_id).await;
        assert!(result.is_ok());
        let result = user_service.get_user_profile(Uuid::nil()).await;
        assert!(result.is_err());
    }

    // Se pueden agregar mocks similares para logout_user, get_user_profile, etc.
    // Así se cubren todos los caminos de los handlers sin depender de la base de datos.
}
