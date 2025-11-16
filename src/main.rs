mod auth;
mod config;
mod database;
mod handlers;
mod middleware;
mod models;
mod services;
mod utils;

use actix_web::{middleware as actix_middleware, web, App, HttpServer, HttpResponse};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use prometheus::{Registry, TextEncoder, Encoder, IntCounter, Opts};
use std::sync::Arc as StdArc;

use auth::{AuthService, RateLimitStore};
use config::AppConfig;
use database::DatabaseService;
use dotenvy::dotenv;
use handlers::*;
use middleware::*;
use services::{SessionService, UserService};

// Shared metrics structure
struct Metrics {
    session_cleanup_runs: IntCounter,
    session_cleanup_removed: IntCounter,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment from .env (if present)
    let _ = dotenv();

    // Load configuration
    let config = match AppConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            // Persist the error if possible or exit with a non-zero code
            std::process::exit(1);
        }
    };

    // Initialize logging: file + stdout (rotating file)
    // Try to initialize flexi_logger to write to a logs directory; fall back to env_logger
    if let Ok(logger) = flexi_logger::Logger::try_with_str(config.logging.level.clone()) {
        let file_spec = flexi_logger::FileSpec::default()
            .directory("logs")
            .suppress_timestamp();
        let _ = logger
            .log_to_file(file_spec)
            .duplicate_to_stdout(flexi_logger::Duplicate::Info)
            .start();
    } else {
        let log_level = utils::logging::level_from_string(&config.logging.level);
        env_logger::builder()
            .filter_level(log_level)
            .format_timestamp_secs()
            .init();
    }

    log::info!(
        "Starting CrazyTrip User Session Server v{}",
        env!("CARGO_PKG_VERSION")
    );
    log::info!("Server: {}:{}", config.server.host, config.server.port);
    log::info!("Database: Connected to PostgreSQL");
    log::info!("Workers: {}", config.server.workers);

    // Initialize database
    let db_service = match DatabaseService::new(&config.database).await {
        Ok(db) => Arc::new(db),
        Err(e) => {
            log::error!("Failed to initialize database: {}", e);
            eprintln!("Failed to initialize database: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize DB schema (create tables) in development if missing
    if let Err(e) = db_service.init_schema().await {
        log::error!("Failed to initialize DB schema: {}", e);
    } else {
        log::info!("DB schema ensured");
    }

    // Initialize auth service
    let auth_service = Arc::new(AuthService::new(config.auth.clone()));

    // Initialize rate limit store
    let rate_limit_store = Arc::new(Mutex::new(RateLimitStore::new()));

    // Initialize user service
    let user_service = Arc::new(UserService::new(
        Arc::clone(&db_service),
        Arc::clone(&auth_service),
    ));

    // Initialize session service
    let session_service = Arc::new(SessionService::new(Arc::clone(&db_service)));

    // Print access information
    println!("🚀 CrazyTrip User Session Server started!");
    println!(
        "📍 Local access: http://{}:{}",
        config.server.host, config.server.port
    );
    println!(
        "📍 Health check: http://{}:{}/health",
        config.server.host, config.server.port
    );
    println!(
        "📍 API docs: http://{}:{}/api/v1/status",
        config.server.host, config.server.port
    );
    println!("🌍 Environment: {}", config.logging.level);
    println!("📝 Press Ctrl+C to stop the server");
    println!();

    // Clone services for background tasks
    let session_service_bg = Arc::clone(&session_service);
    let db_for_bg = Arc::clone(&db_service);

    // Initialize Prometheus registry and exporter
    let registry = Registry::new();

    // Create and register basic metrics so /metrics is not empty
    let cleanup_runs_opts = Opts::new("session_cleanup_runs_total", "Number of session cleanup runs");
    let session_cleanup_runs = IntCounter::with_opts(cleanup_runs_opts).unwrap();
    registry.register(Box::new(session_cleanup_runs.clone())).ok();

    let cleanup_removed_opts = Opts::new("session_cleanup_removed_total", "Number of sessions removed by cleanup");
    let session_cleanup_removed = IntCounter::with_opts(cleanup_removed_opts).unwrap();
    registry.register(Box::new(session_cleanup_removed.clone())).ok();

    // Wrap metrics in an Arc so background tasks and handlers can share them
    let metrics = StdArc::new(Metrics {
        session_cleanup_runs,
        session_cleanup_removed,
    });

    let prometheus_data = web::Data::new(registry.clone());
    let metrics_data = web::Data::new(metrics.clone());

    // Spawn background task for session cleanup
    let metrics_bg = StdArc::clone(&metrics);
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
            match session_service_bg.cleanup_expired_sessions().await {
                Ok(removed) => {
                    // increment prometheus counters
                    metrics_bg.session_cleanup_runs.inc();
                    metrics_bg.session_cleanup_removed.inc_by(removed as u64);

                    if let Err(e) = db_for_bg.insert_metric_aggregate(
                        "session_cleanup_removed",
                        Some(serde_json::json!({ "job": "session_cleanup" })),
                        removed as f64,
                    ).await {
                        log::error!("Failed to persist session cleanup metric: {}", e);
                    }
                    log::info!("Cleaned up expired sessions: {}", removed);
                }
                Err(e) => {
                    log::error!("Failed to cleanup expired sessions: {}", e);
                // Persist error to DB for auditing
                    let db_clone = Arc::clone(&db_for_bg);
                    let err_str = e.to_string();
                    tokio::spawn(async move {
                        let _ = utils::log_internal_error(
                            db_clone,
                            "ERROR",
                            "cleanup_expired_sessions",
                            "Failed to cleanup expired sessions",
                            Some(serde_json::json!({"error": err_str})),
                            None,
                            None,
                        )
                        .await;
                    });
                }
            }
        }
    });

    // Create and run the HTTP server
    HttpServer::new(move || {
        App::new()
            // Shared data
            .app_data(web::Data::new(Arc::clone(&db_service)))
            .app_data(web::Data::new(Arc::clone(&auth_service)))
            .app_data(web::Data::new(Arc::clone(&user_service)))
            .app_data(web::Data::new(Arc::clone(&session_service)))
            .app_data(prometheus_data.clone())
            .app_data(metrics_data.clone())
            // Custom middleware (applied before compression to work with original body types)
            .wrap(LoggingMiddleware)
            .wrap(RequestSizeLimitMiddleware {
                max_size: config.security.max_request_size_bytes,
            })
            .wrap(RateLimitMiddleware {
                store: Arc::clone(&rate_limit_store),
                max_requests: config.security.rate_limit_requests,
                window_seconds: config.security.rate_limit_window_seconds,
                auth_service: Some(Arc::clone(&auth_service)),
            })
            .wrap(CorsMiddleware {
                allowed_origins: config.security.cors_allowed_origins.clone(),
            })
            .wrap(SecurityHeadersMiddleware {
                content_security_policy: config.security.content_security_policy.clone(),
                hsts_preload: config.security.hsts_preload,
                hsts_max_age_seconds: config.security.hsts_max_age_seconds,
                hsts_include_subdomains: config.security.hsts_include_subdomains,
                referrer_policy: config.security.referrer_policy.clone(),
                permissions_policy: config.security.permissions_policy.clone(),
            })
            .wrap(AuthMiddleware {
                auth_service: Arc::clone(&auth_service),
                db_service: Arc::clone(&db_service),
            })
            // Actix built-in middleware (applied after custom middleware to avoid body type conflicts)
            .wrap(actix_middleware::Compress::default())
            // Public routes (no auth required)
            .service({
                // Build the scope with public routes
                web::scope("/api/v1")
                    .route("/status", web::get().to(server_status))
                    .route("/health", web::get().to(health_check))
                    .route("/ready", web::get().to(readiness_check))
                    // Prometheus metrics endpoint (scraped externally)
                    .route("/metrics", web::get().to(|registry: web::Data<Registry>| async move {
                        let encoder = TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = Vec::new();
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        let text = String::from_utf8(buffer).unwrap_or_default();
                        HttpResponse::Ok()
                            .content_type("text/plain; version=0.0.4; charset=utf-8")
                            .body(text)
                    }))
                    // JSON representation of metrics (simple wrapper with text metrics)
                    .route("/metrics/json", web::get().to(|registry: web::Data<Registry>| async move {
                        let encoder = TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = Vec::new();
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        let text = String::from_utf8(buffer).unwrap_or_default();
                        HttpResponse::Ok()
                            .content_type("application/json")
                            .json(serde_json::json!({ "metrics": text }))
                    }))
                    .route("/auth/register", web::post().to(register_user))
                    .route("/auth/login", web::post().to(login_user))
                    .route("/auth/refresh", web::post().to(refresh_token))
                    .route(
                        "/auth/request-reset",
                        web::post().to(request_password_reset),
                    )
                    .route("/auth/reset-password", web::post().to(reset_password))
                    .route("/auth/verify-email", web::post().to(verify_email))
            })
            // Protected routes (auth required)
            .service(
                web::scope("/api/v1")
                    .route("/auth/logout", web::post().to(logout_user))
                    .route(
                        "/auth/resend-verification",
                        web::post().to(resend_verification_email),
                    )
                    .route("/user/profile", web::get().to(get_user_profile))
                    .route("/user/profile", web::put().to(update_user_profile))
                    .route("/user/deactivate", web::post().to(deactivate_user))
                    .route("/user/sessions", web::get().to(get_user_sessions))
                    .route(
                        "/user/sessions/invalidate-other",
                        web::post().to(invalidate_other_sessions),
                    )
                    .route(
                        "/user/sessions/active-count",
                        web::get().to(get_active_session_count),
                    )
                    .route(
                        "/user/sessions/{session_id}",
                        web::delete().to(invalidate_session),
                    )
                    // Admin routes (would need additional role checking middleware)
                    .route("/admin/users", web::get().to(get_all_users))
                    .route(
                        "/admin/users/{user_id}/deactivate",
                        web::post().to(admin_deactivate_user),
                    ),
            )
    })
    .bind((config.server.host.clone(), config.server.port))?
    .workers(config.server.workers)
    // Apply server timeouts and connection settings
    .keep_alive(std::time::Duration::from_secs(
        config.server.keep_alive_seconds,
    ))
    .client_request_timeout(std::time::Duration::from_secs(
        config.server.client_timeout_seconds,
    ))
    .client_disconnect_timeout(std::time::Duration::from_secs(
        config.server.client_shutdown_seconds,
    ))
    .max_connections(config.server.max_connections)
    .run()
    .await
}
