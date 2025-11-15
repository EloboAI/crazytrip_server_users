#[cfg(test)]
mod tests {
    use actix_web::{test, web, App, HttpResponse, Result as ActixResult};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct HealthResponse {
        status: String,
        timestamp: String,
        version: String,
    }

    #[derive(Serialize, Deserialize)]
    struct StatusResponse {
        status: String,
        message: String,
        server: String,
        timestamp: String,
    }

    async fn health_check() -> ActixResult<HttpResponse> {
        let response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        Ok(HttpResponse::Ok().json(response))
    }

    async fn api_status() -> ActixResult<HttpResponse> {
        let response = StatusResponse {
            status: "ok".to_string(),
            message: "CrazyTrip User Session Server is running".to_string(),
            server: "actix-web".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        Ok(HttpResponse::Ok().json(response))
    }

    #[actix_rt::test]
    async fn test_health_check() {
        let app =
            test::init_service(App::new().route("/health", web::get().to(health_check))).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body: HealthResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "healthy");
        assert!(!body.timestamp.is_empty());
        assert!(!body.version.is_empty());
    }

    #[actix_rt::test]
    async fn test_api_status() {
        let app =
            test::init_service(App::new().route("/api/v1/status", web::get().to(api_status))).await;

        let req = test::TestRequest::get().uri("/api/v1/status").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body: StatusResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "ok");
        assert!(body.message.contains("CrazyTrip"));
        assert_eq!(body.server, "actix-web");
        assert!(!body.timestamp.is_empty());
    }
}
