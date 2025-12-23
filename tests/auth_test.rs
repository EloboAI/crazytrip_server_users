#[cfg(test)]
mod tests {
    use actix_web::{test, web, App, HttpResponse, Result as ActixResult};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct RegisterRequest {
        email: String,
        username: String,
        password: String,
    }

    #[derive(Serialize, Deserialize)]
    struct RegisterResponse {
        user_id: String,
        email: String,
        username: String,
        status: String,
    }

    async fn register_user(req: web::Json<RegisterRequest>) -> ActixResult<HttpResponse> {
        if req.email.is_empty() || !req.email.contains('@') || req.password.len() < 8 {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Email válido y password >= 8 caracteres requeridos"
            })));
        }
        let resp = RegisterResponse {
            user_id: "user-123".to_string(),
            email: req.email.clone(),
            username: req.username.clone(),
            status: "registered".to_string(),
        };
        Ok(HttpResponse::Ok().json(resp))
    }

    #[actix_rt::test]
    async fn test_register_user_success() {
        let app = test::init_service(App::new().route("/auth/register", web::post().to(register_user))).await;
        let req_body = RegisterRequest {
            email: "test@crazytrip.com".to_string(),
            username: "testuser".to_string(),
            password: "TestPass123".to_string(),
        };
        let req = test::TestRequest::post().uri("/auth/register").set_json(&req_body).to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body: RegisterResponse = test::read_body_json(resp).await;
        assert_eq!(body.email, "test@crazytrip.com");
        assert_eq!(body.status, "registered");
    }

    #[actix_rt::test]
    async fn test_register_user_invalid_email() {
        let app = test::init_service(App::new().route("/auth/register", web::post().to(register_user))).await;
        let req_body = RegisterRequest {
            email: "bademail".to_string(),
            username: "testuser".to_string(),
            password: "TestPass123".to_string(),
        };
        let req = test::TestRequest::post().uri("/auth/register").set_json(&req_body).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Email válido y password >= 8 caracteres requeridos");
    }

    #[actix_rt::test]
    async fn test_register_user_short_password() {
        let app = test::init_service(App::new().route("/auth/register", web::post().to(register_user))).await;
        let req_body = RegisterRequest {
            email: "test@crazytrip.com".to_string(),
            username: "testuser".to_string(),
            password: "short".to_string(),
        };
        let req = test::TestRequest::post().uri("/auth/register").set_json(&req_body).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Email válido y password >= 8 caracteres requeridos");
    }
}
