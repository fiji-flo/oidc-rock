//! OIDC Rock - Simple OIDC Provider for Testing
//!
//! A lightweight OpenID Connect (OIDC) provider built with Rust and Axum,
//! designed for testing and development purposes. All data is stored in memory
//! and configured via YAML files.
use axum::{
    Router,
    routing::{get, post},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time;
use tower_http::cors::CorsLayer;
use tracing::{error, info};
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

pub async fn run() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.yaml".to_string());

    let config = Config::from_file(&config_path).await?;
    info!("Loaded configuration from {}", config_path);

    // Initialize storage
    let storage = InMemoryStorage::new(&config);

    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
    };

    // Start cleanup task for expired tokens
    let cleanup_storage = state.storage.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_storage.cleanup_expired().await {
                error!("Failed to cleanup expired tokens: {}", e);
            } else {
                info!("Cleaned up expired tokens");
            }
        }
    });

    // Build the application routes
    let app = Router::new()
        // OIDC Discovery endpoint
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery),
        )
        // OIDC Core endpoints
        .route("/auth", get(handlers::authorize))
        .route("/token", post(handlers::token))
        .route("/userinfo", get(handlers::userinfo))
        .route("/.well-known/jwks.json", get(handlers::jwks))
        // Custom endpoints for testing
        .route("/login", get(handlers::login_form).post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/", get(handlers::index))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3080));
    info!("Starting OIDC provider on http://{}", addr);
    info!(
        "Discovery endpoint: http://{}/.well-known/openid-configuration",
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
