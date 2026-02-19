//! OIDC Rock - Simple OIDC Provider for Testing
//!
//! A lightweight OpenID Connect (OIDC) provider built with Rust and Axum,
//! designed for testing and development purposes. All data is stored in memory
//! and configured via YAML files.
use axum::{
    Router,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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
    // Initialize rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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
        config: Arc::new(config.clone()),
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
        .route("/revoke", post(handlers::revoke))
        .route("/userinfo", get(handlers::userinfo))
        .route("/.well-known/jwks.json", get(handlers::jwks))
        // Custom endpoints for testing
        .route("/login", get(handlers::login_form).post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/", get(handlers::index))
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    // Parse the host address
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, state.config.server.port));

    // Determine protocol for logging
    let protocol = if state
        .config
        .server
        .tls
        .as_ref()
        .map(|t| t.enabled)
        .unwrap_or(false)
    {
        "https"
    } else {
        "http"
    };

    info!("Starting OIDC provider on {}://{}", protocol, addr);
    info!(
        "Discovery endpoint: {}://{}/.well-known/openid-configuration",
        protocol, addr
    );

    // Check if TLS is enabled
    if let Some(tls_config) = &state.config.server.tls {
        if tls_config.enabled {
            info!("Server listening on {} with TLS enabled", addr);

            let rustls_config =
                RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await?;

            axum_server::bind_rustls(addr, rustls_config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        } else {
            info!("Server listening on {} (TLS disabled)", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    } else {
        info!("Server listening on {} (no TLS configuration)", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    info!("Server shutdown complete");
    Ok(())
}
