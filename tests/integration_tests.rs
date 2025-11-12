use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use oidc_rock::{config::Config, storage::InMemoryStorage, AppState};
use serde_json::Value;
use std::sync::Arc;
use tower::util::ServiceExt;
use tower_http::cors::CorsLayer;

// Helper function to create test app
fn create_test_app() -> Router {
    let config = Config::default();
    let storage = InMemoryStorage::new(&config);
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(config),
    };

    Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(oidc_rock::handlers::discovery),
        )
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(oidc_rock::handlers::jwks),
        )
        .route("/auth", axum::routing::get(oidc_rock::handlers::authorize))
        .route("/token", axum::routing::post(oidc_rock::handlers::token))
        .route(
            "/userinfo",
            axum::routing::get(oidc_rock::handlers::userinfo),
        )
        .route(
            "/login",
            axum::routing::get(oidc_rock::handlers::login_form).post(oidc_rock::handlers::login),
        )
        .route("/logout", axum::routing::post(oidc_rock::handlers::logout))
        .route("/", axum::routing::get(oidc_rock::handlers::index))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[tokio::test]
async fn test_discovery_endpoint() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/.well-known/openid-configuration")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let discovery: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(discovery["issuer"], "http://127.0.0.1:3080");
    assert_eq!(
        discovery["authorization_endpoint"],
        "http://127.0.0.1:3080/auth"
    );
    assert_eq!(discovery["token_endpoint"], "http://127.0.0.1:3080/token");
    assert_eq!(
        discovery["userinfo_endpoint"],
        "http://127.0.0.1:3080/userinfo"
    );
    assert!(discovery["scopes_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::String("openid".to_string())));
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/.well-known/jwks.json")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let jwks: Value = serde_json::from_slice(&body).unwrap();

    assert!(jwks.get("keys").is_some());
    assert!(jwks["keys"].is_array());
}

#[tokio::test]
async fn test_authorization_endpoint_invalid_client() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/auth?client_id=invalid-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorization_endpoint_valid_client() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/auth?client_id=test-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20profile")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should redirect to login page
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("/login"));
    assert!(location.contains("client_id=test-client"));
}

#[tokio::test]
async fn test_login_form() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/login?client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("Login to OIDC Rock"));
    assert!(html.contains("test-client"));
    assert!(html.contains("username"));
    assert!(html.contains("password"));
}

#[tokio::test]
async fn test_token_endpoint_missing_code() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/token")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&client_id=test-client",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_endpoint_invalid_grant_type() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/token")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=invalid_grant"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_userinfo_endpoint_no_token() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/userinfo")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(error["error"], "invalid_token");
    assert_eq!(error["error_description"], "Missing authorization header");
}

#[tokio::test]
async fn test_userinfo_endpoint_invalid_token_format() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/userinfo")
        .header("authorization", "Invalid token-format")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(error["error"], "invalid_token");
    assert_eq!(
        error["error_description"],
        "Invalid token type. Expected Bearer token"
    );
}

#[tokio::test]
async fn test_userinfo_endpoint_invalid_jwt() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/userinfo")
        .header("authorization", "Bearer invalid.jwt.token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(error["error"], "invalid_token");
    assert_eq!(
        error["error_description"],
        "Invalid or expired access token"
    );
}

#[tokio::test]
async fn test_home_page() {
    let app = create_test_app();

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("OIDC Rock - Test OIDC Provider"));
    assert!(html.contains("Discovery"));
    assert!(html.contains("Authorization"));
    assert!(html.contains("testuser"));
    assert!(html.contains("test-client"));
}

#[tokio::test]
async fn test_logout_endpoint() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/logout")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(""))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("Successfully Logged Out"));
    assert!(html.contains("session and tokens have been invalidated"));
}

#[tokio::test]
async fn test_logout_with_redirect() {
    let app = create_test_app();

    let request = Request::builder()
        .uri("/logout")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "post_logout_redirect_uri=https://example.com/logged-out",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "https://example.com/logged-out");
}

// Integration test for storage functionality
#[tokio::test]
async fn test_storage_operations() {
    let config = Config::default();
    let storage = InMemoryStorage::new(&config);

    // Test user verification
    assert!(storage.verify_user_password("testuser", "password"));
    assert!(!storage.verify_user_password("testuser", "wrong-password"));
    assert!(!storage.verify_user_password("nonexistent", "password"));

    // Test session management
    let session = storage.create_session("testuser").await.unwrap();
    assert!(storage.is_session_valid(&session.session_id).await);

    storage.delete_session(&session.session_id).await.unwrap();
    assert!(!storage.is_session_valid(&session.session_id).await);

    // Test authorization code flow
    let auth_code = storage
        .create_authorization_code(
            "test-client",
            "testuser",
            "http://localhost:8080/callback",
            "openid profile",
            None,
            None,
            Some("test-nonce".to_string()),
        )
        .await
        .unwrap();

    assert!(storage.is_authorization_code_valid(&auth_code.code).await);
    assert_eq!(auth_code.nonce, Some("test-nonce".to_string()));

    let consumed = storage
        .consume_authorization_code(&auth_code.code)
        .await
        .unwrap();
    assert_eq!(consumed.user_id, "testuser");
    assert_eq!(consumed.client_id, "test-client");
    assert_eq!(consumed.nonce, Some("test-nonce".to_string()));

    // Should not be valid after consumption
    assert!(!storage.is_authorization_code_valid(&auth_code.code).await);

    // Test token management
    let access_token = storage
        .create_access_token("test-client", "testuser", "openid profile", 3600)
        .await
        .unwrap();

    assert!(storage.is_access_token_valid(&access_token.token).await);

    let refresh_token = storage
        .create_refresh_token("test-client", "testuser", "openid profile")
        .await
        .unwrap();

    assert!(storage.is_refresh_token_valid(&refresh_token.token).await);

    // Test token revocation
    storage
        .revoke_access_token(&access_token.token)
        .await
        .unwrap();
    assert!(!storage.is_access_token_valid(&access_token.token).await);

    storage
        .revoke_refresh_token(&refresh_token.token)
        .await
        .unwrap();
    assert!(!storage.is_refresh_token_valid(&refresh_token.token).await);
}

// Test JWT functionality
#[tokio::test]
async fn test_jwt_operations() {
    use chrono::Utc;
    use oidc_rock::crypto::JwtManager;
    use oidc_rock::models::{AccessTokenClaims, IdTokenClaims};
    use std::collections::HashMap;

    let jwt_manager = JwtManager::new();

    // Test ID token creation and validation
    let id_claims = IdTokenClaims {
        iss: "test-issuer".to_string(),
        sub: "test-user".to_string(),
        aud: "test-client".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        auth_time: Some(Utc::now().timestamp()),
        nonce: Some("test-nonce".to_string()),
        name: Some("Test User".to_string()),
        given_name: Some("Test".to_string()),
        family_name: Some("User".to_string()),
        email: Some("test@example.com".to_string()),
        email_verified: Some(true),
        picture: None,
        additional_claims: HashMap::new(),
    };

    let id_token = jwt_manager.create_id_token(id_claims.clone()).unwrap();
    let decoded_id = jwt_manager.validate_id_token(&id_token).unwrap();

    assert_eq!(decoded_id.sub, id_claims.sub);
    assert_eq!(decoded_id.aud, id_claims.aud);
    assert_eq!(decoded_id.nonce, id_claims.nonce);
    assert_eq!(decoded_id.email, id_claims.email);

    // Test access token creation and validation
    let access_claims = AccessTokenClaims {
        iss: "test-issuer".to_string(),
        sub: "test-user".to_string(),
        aud: "test-client".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        scope: "openid profile email".to_string(),
        client_id: "test-client".to_string(),
    };

    let access_token = jwt_manager
        .create_access_token(access_claims.clone())
        .unwrap();
    let decoded_access = jwt_manager.validate_access_token(&access_token).unwrap();

    assert_eq!(decoded_access.sub, access_claims.sub);
    assert_eq!(decoded_access.scope, access_claims.scope);
    assert_eq!(decoded_access.client_id, access_claims.client_id);
}

// Test configuration loading
#[tokio::test]
async fn test_config_operations() {
    let config = Config::default();

    // Test client lookup
    let client = config.get_client("test-client").unwrap();
    assert_eq!(client.client_id, "test-client");
    assert_eq!(client.client_secret, Some("test-secret".to_string()));
    assert!(client
        .redirect_uris
        .contains(&"http://localhost:8080/callback".to_string()));

    // Test user lookup
    let user = config.get_user("testuser").unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.name, "Test User");

    // Test non-existent lookups
    assert!(config.get_client("nonexistent").is_none());
    assert!(config.get_user("nonexistent").is_none());
}
