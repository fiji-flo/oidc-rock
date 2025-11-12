//! OIDC Rock - Simple OIDC Provider for Testing
//!
//! A lightweight OpenID Connect (OIDC) provider built with Rust and Axum,
//! designed for testing and development purposes. All data is stored in memory
//! and configured via YAML files.

pub mod config;
pub mod crypto;
pub mod handlers;
pub mod models;
pub mod storage;

pub use config::Config;
pub use storage::InMemoryStorage;

#[derive(Clone)]
pub struct AppState {
    pub storage: std::sync::Arc<InMemoryStorage>,
    pub config: std::sync::Arc<Config>,
}
