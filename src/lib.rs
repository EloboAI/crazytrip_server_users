pub mod auth;
pub mod config;
pub mod database;
pub mod handlers;
pub mod models;
pub mod services;
pub mod utils;

// Note: avoid glob re-exports to prevent ambiguous symbol re-exports
// Consumers should reference items through their module paths, e.g.:
// `crate::models::User` or `crate::utils::PaginationParams`.
