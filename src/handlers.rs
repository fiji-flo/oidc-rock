use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect},
};
use chrono::Utc;

use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::AppState;
use crate::crypto::{JwtManager, verify_code_challenge};
use crate::models::{
    AccessTokenClaims, AuthorizeRequest, DiscoveryDocument, ErrorResponse, IdTokenClaims,
    LoginRequest, TokenRequest, TokenResponse, UserInfoResponse,
};

// Index page - simple info about the OIDC provider
pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>OIDC Rck - Test Provider</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .endpoint {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        code {{ background: #e0e0e0; padding: 2px 4px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>OIDC Rock - Test OIDC Provider</h1>
    <p>This is a simple OpenID Connect provider for testing purposes.</p>

    <h2>Configuration</h2>
    <div class="endpoint">
        <strong>Issuer:</strong> <code>{}</code><br>
        <strong>Base URL:</strong> <code>{}</code>
    </div>

    <h2>OIDC Endpoints</h2>
    <div class="endpoint">
        <strong>Discovery:</strong> <a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a>
    </div>
    <div class="endpoint">
        <strong>Authorization:</strong> <code>/auth</code>
    </div>
    <div class="endpoint">
        <strong>Token:</strong> <code>/token</code>
    </div>
    <div class="endpoint">
        <strong>UserInfo:</strong> <code>/userinfo</code>
    </div>

    <h2>Test Endpoints</h2>
    <div class="endpoint">
        <strong>Login:</strong> <a href="/login">/login</a>
    </div>

    <h2>Default Test Client</h2>
    <div class="endpoint">
        <strong>Client ID:</strong> <code>test-client</code><br>
        <strong>Client Secret:</strong> <code>test-secret</code><br>
        <strong>Redirect URI:</strong> <code>http://localhost:8080/callback</code>
    </div>

    <h2>Default Test User</h2>
    <div class="endpoint">
        <strong>Username:</strong> <code>testuser</code><br>
        <strong>Password:</strong> <code>password</code>
    </div>
</body>
</html>
"#,
        state.config.oidc.issuer, state.config.server.base_url
    );

    Html(html)
}

// OIDC Discovery endpoint
pub async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let base_url = &state.config.server.base_url;

    let discovery = DiscoveryDocument {
        issuer: state.config.oidc.issuer.clone(),
        authorization_endpoint: format!("{}/auth", base_url),
        token_endpoint: format!("{}/token", base_url),
        userinfo_endpoint: format!("{}/userinfo", base_url),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        scopes_supported: state.config.oidc.supported_scopes.clone(),
        response_types_supported: state.config.oidc.supported_response_types.clone(),
        grant_types_supported: state.config.oidc.supported_grant_types.clone(),
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".to_string(),
            "client_secret_basic".to_string(),
        ],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "auth_time".to_string(),
            "name".to_string(),
            "given_name".to_string(),
            "family_name".to_string(),
            "email".to_string(),
            "email_verified".to_string(),
            "picture".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
    };

    Json(discovery)
}

// Authorization endpoint
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeRequest>,
) -> axum::response::Response {
    info!("Authorization request: {:?}", params);

    // Validate client
    let client = match state.config.get_client(&params.client_id) {
        Some(client) => client,
        None => {
            warn!("Unknown client: {}", params.client_id);
            return create_error_response("invalid_client", "Unknown client").into_response();
        }
    };

    // Validate redirect URI
    if !client.redirect_uris.contains(&params.redirect_uri) {
        warn!("Invalid redirect URI: {}", params.redirect_uri);
        return create_error_response("invalid_request", "Invalid redirect URI").into_response();
    }

    // Validate response type
    if !client.response_types.contains(&params.response_type) {
        warn!("Unsupported response type: {}", params.response_type);
        return create_error_redirect(
            &params.redirect_uri,
            "unsupported_response_type",
            "Unsupported response type",
            params.state.as_deref(),
        )
        .into_response();
    }

    // For now, redirect to login page with the original parameters
    let mut login_url = format!(
        "/login?client_id={}&redirect_uri={}&scope={}&state={}&response_type={}",
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&params.redirect_uri),
        urlencoding::encode(&params.scope.unwrap_or_default()),
        urlencoding::encode(&params.state.unwrap_or_default()),
        urlencoding::encode(&params.response_type)
    );

    // Add nonce if present
    if let Some(nonce) = &params.nonce {
        login_url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }

    // Add login_hint if present
    if let Some(login_hint) = &params.login_hint {
        login_url.push_str(&format!("&login_hint={}", urlencoding::encode(login_hint)));
    }

    // Add PKCE parameters if present
    if let Some(challenge) = &params.code_challenge {
        login_url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(challenge)
        ));
    }
    if let Some(method) = &params.code_challenge_method {
        login_url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }

    Redirect::to(&login_url).into_response()
}

// Login form
pub async fn login_form(
    State(_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_id = params.get("client_id").unwrap_or(&"".to_string()).clone();
    let login_hint = params.get("login_hint");
    let redirect_uri = params
        .get("redirect_uri")
        .unwrap_or(&"".to_string())
        .clone();
    let scope = params.get("scope").unwrap_or(&"".to_string()).clone();
    let state = params.get("state").unwrap_or(&"".to_string()).clone();
    let nonce = params.get("nonce").unwrap_or(&"".to_string()).clone();
    let code_challenge = params
        .get("code_challenge")
        .unwrap_or(&"".to_string())
        .clone();
    let code_challenge_method = params
        .get("code_challenge_method")
        .unwrap_or(&"".to_string())
        .clone();

    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Login - OIDC Rock</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
        form {{ background: #f9f9f9; padding: 20px; border-radius: 8px; }}
        input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }}
        button {{ width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #005a87; }}
        .info {{ background: #e7f3ff; padding: 10px; margin-bottom: 20px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h2>Login to OIDC Rock</h2>

    <div class="info">
        <strong>Client:</strong> {}<br>
        <strong>Requested Scopes:</strong> {}
    </div>

    <form method="post" action="/login">
        <input type="hidden" name="client_id" value="{}">
        <input type="hidden" name="redirect_uri" value="{}">
        <input type="hidden" name="scope" value="{}">
        <input type="hidden" name="state" value="{}">
        <input type="hidden" name="nonce" value="{}">
        <input type="hidden" name="code_challenge" value="{}">
        <input type="hidden" name="code_challenge_method" value="{}">

        <input type="text" name="username" placeholder="Username" value="{}" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>

    <p style="text-align: center; color: #666; font-size: 14px;">
        Default: testuser / password
    </p>
</body>
</html>
"#,
        client_id,
        scope,
        client_id,
        redirect_uri,
        scope,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
        login_hint.map(|s| s.as_str()).unwrap_or_default()
    );

    Html(html)
}

// Login processing
pub async fn login(
    State(state): State<AppState>,
    Form(login_request): Form<LoginRequest>,
) -> impl IntoResponse {
    info!("Login attempt for user: {}", login_request.username);

    // Verify credentials
    if !state
        .storage
        .verify_user_password(&login_request.username, &login_request.password)
    {
        warn!("Invalid credentials for user: {}", login_request.username);
        return Html(
            r#"
<!DOCTYPE html>
<html>
<body>
    <h2>Login Failed</h2>
    <p>Invalid username or password.</p>
    <a href="javascript:history.back()">Go back</a>
</body>
</html>
"#,
        )
        .into_response();
    }

    let state_param = login_request.state.unwrap_or_default();

    // Create authorization code
    match state
        .storage
        .create_authorization_code(
            &login_request.client_id,
            &login_request.username,
            &login_request.redirect_uri,
            &login_request.scope,
            login_request.code_challenge.clone(),
            login_request.code_challenge_method.clone(),
            login_request.nonce.clone(),
        )
        .await
    {
        Ok(auth_code) => {
            info!(
                "Created authorization code for user: {}",
                login_request.username
            );

            let redirect_url = if state_param.is_empty() {
                format!("{}?code={}", login_request.redirect_uri, auth_code.code)
            } else {
                format!(
                    "{}?code={}&state={}",
                    login_request.redirect_uri, auth_code.code, state_param
                )
            };

            Redirect::to(&redirect_url).into_response()
        }
        Err(e) => {
            error!("Failed to create authorization code: {}", e);
            Html(
                r#"
<!DOCTYPE html>
<html>
<body>
    <h2>Error</h2>
    <p>Failed to process login. Please try again.</p>
    <a href="javascript:history.back()">Go back</a>
</body>
</html>
"#,
            )
            .into_response()
        }
    }
}

// Token endpoint
pub async fn token(
    State(state): State<AppState>,
    Form(token_request): Form<TokenRequest>,
) -> axum::response::Response {
    info!("Token request: grant_type={}", token_request.grant_type);

    match token_request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, token_request)
            .await
            .into_response(),
        "refresh_token" => handle_refresh_token_grant(state, token_request)
            .await
            .into_response(),
        _ => Json(ErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: Some("Grant type not supported".to_string()),
            error_uri: None,
        })
        .into_response(),
    }
}

async fn handle_authorization_code_grant(
    state: AppState,
    token_request: TokenRequest,
) -> impl IntoResponse {
    let code = match &token_request.code {
        Some(code) => code,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: Some("Missing authorization code".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Consume authorization code
    let auth_code = match state.storage.consume_authorization_code(code).await {
        Ok(auth_code) => auth_code,
        Err(_) => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Invalid or expired authorization code".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    let client_id = match &token_request.client_id {
        Some(client_id) => client_id,
        None => auth_code.client_id.as_str(),
    };

    // Validate client
    let client = match state.config.get_client(client_id) {
        Some(client) => client,
        None => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: Some("Unknown client".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Validate client secret if provided
    if let Some(provided_secret) = &token_request.client_secret
        && let Some(expected_secret) = &client.client_secret
        && provided_secret != expected_secret
    {
        return Json(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: Some("Invalid client secret".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Validate redirect URI
    if let Some(redirect_uri) = &token_request.redirect_uri
        && redirect_uri != &auth_code.redirect_uri
    {
        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("Redirect URI mismatch".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Validate PKCE if code challenge was used
    if let Some(challenge) = &auth_code.code_challenge {
        let verifier = match &token_request.code_verifier {
            Some(verifier) => verifier,
            None => {
                return Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some(
                        "code_verifier is required when code_challenge was used".to_string(),
                    ),
                    error_uri: None,
                })
                .into_response();
            }
        };

        let method = auth_code
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");

        if !verify_code_challenge(verifier, challenge, method) {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("PKCE verification failed".to_string()),
                error_uri: None,
            })
            .into_response();
        }

        info!("PKCE verification successful for client: {}", client_id);
    }

    // Create tokens
    let jwt_manager = JwtManager::default();
    let expires_in = state.config.oidc.token_expiry_seconds;

    // Create access token
    let access_token_claims = AccessTokenClaims {
        iss: state.config.oidc.issuer.clone(),
        sub: auth_code.user_id.clone(),
        aud: auth_code.client_id.clone(),
        exp: (Utc::now().timestamp() + expires_in as i64),
        iat: Utc::now().timestamp(),
        scope: auth_code.scope.clone(),
        client_id: auth_code.client_id.clone(),
    };

    let access_token = match jwt_manager.create_access_token(access_token_claims) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to create access token: {}", e);
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Failed to create access token".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Create ID token if openid scope is requested
    let id_token = if auth_code.scope.contains("openid") {
        let user = state.storage.get_user(&auth_code.user_id);

        let mut id_token_claims = IdTokenClaims {
            iss: state.config.oidc.issuer.clone(),
            sub: auth_code.user_id.clone(),
            aud: auth_code.client_id.clone(),
            exp: (Utc::now().timestamp() + expires_in as i64),
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: auth_code.nonce.clone(),
            name: None,
            given_name: None,
            family_name: None,
            email: None,
            email_verified: None,
            picture: None,
            additional_claims: HashMap::new(),
        };

        // Add user claims if available
        if let Some(user) = user {
            if auth_code.scope.contains("profile") {
                id_token_claims.name = Some(user.name.clone());
                id_token_claims.given_name = user.given_name.clone();
                id_token_claims.family_name = user.family_name.clone();
                id_token_claims.picture = user.picture.clone();
            }
            if auth_code.scope.contains("email") {
                id_token_claims.email = Some(user.email.clone());
                id_token_claims.email_verified = Some(true);
            }

            // Add custom claims
            if let Some(custom_claims) = &user.claims {
                id_token_claims.additional_claims = custom_claims.clone();
            }
        }

        match jwt_manager.create_id_token(id_token_claims) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Failed to create ID token: {}", e);
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: Some("Failed to create ID token".to_string()),
                    error_uri: None,
                })
                .into_response();
            }
        }
    } else {
        None
    };

    // Create refresh token
    let refresh_token = if client.grant_types.contains(&"refresh_token".to_string()) {
        match state
            .storage
            .create_refresh_token(client_id, &auth_code.user_id, &auth_code.scope)
            .await
        {
            Ok(token) => Some(token.token),
            Err(e) => {
                error!("Failed to create refresh token: {}", e);
                None
            }
        }
    } else {
        None
    };

    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        refresh_token,
        scope: auth_code.scope,
    };

    Json(response).into_response()
}

async fn handle_refresh_token_grant(
    state: AppState,
    token_request: TokenRequest,
) -> impl IntoResponse {
    let refresh_token_str = match &token_request.refresh_token {
        Some(token) => token,
        None => {
            return Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: Some("Missing refresh_token parameter".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    let client_id = match &token_request.client_id {
        Some(client_id) => client_id,
        None => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: Some("Missing client_id".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Validate client
    let client = match state.config.get_client(client_id) {
        Some(client) => client,
        None => {
            return Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: Some("Unknown client".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Validate client secret if provided
    if let Some(provided_secret) = &token_request.client_secret
        && let Some(expected_secret) = &client.client_secret
        && provided_secret != expected_secret
    {
        return Json(ErrorResponse {
            error: "invalid_client".to_string(),
            error_description: Some("Invalid client secret".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Get refresh token from storage
    let refresh_token = match state.storage.get_refresh_token(refresh_token_str).await {
        Some(token) => token,
        None => {
            return Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Invalid refresh token".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Check if refresh token is valid
    if !state
        .storage
        .is_refresh_token_valid(refresh_token_str)
        .await
    {
        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("Refresh token has expired".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Validate client matches
    if refresh_token.client_id != *client_id {
        return Json(ErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: Some("Client ID mismatch".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Create new tokens
    let jwt_manager = JwtManager::default();
    let expires_in = state.config.oidc.token_expiry_seconds;

    // Create new access token
    let access_token_claims = AccessTokenClaims {
        iss: state.config.oidc.issuer.clone(),
        sub: refresh_token.user_id.clone(),
        aud: client_id.clone(),
        exp: (Utc::now().timestamp() + expires_in as i64),
        iat: Utc::now().timestamp(),
        scope: refresh_token.scope.clone(),
        client_id: client_id.clone(),
    };

    let access_token = match jwt_manager.create_access_token(access_token_claims) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to create access token: {}", e);
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Failed to create access token".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Create new ID token if openid scope is present
    let id_token = if refresh_token.scope.contains("openid") {
        let user = state.storage.get_user(&refresh_token.user_id);

        let mut id_token_claims = IdTokenClaims {
            iss: state.config.oidc.issuer.clone(),
            sub: refresh_token.user_id.clone(),
            aud: client_id.clone(),
            exp: (Utc::now().timestamp() + expires_in as i64),
            iat: Utc::now().timestamp(),
            auth_time: Some(Utc::now().timestamp()),
            nonce: None,
            name: None,
            given_name: None,
            family_name: None,
            email: None,
            email_verified: None,
            picture: None,
            additional_claims: HashMap::new(),
        };

        // Add user claims if available
        if let Some(user) = user {
            if refresh_token.scope.contains("profile") {
                id_token_claims.name = Some(user.name.clone());
                id_token_claims.given_name = user.given_name.clone();
                id_token_claims.family_name = user.family_name.clone();
                id_token_claims.picture = user.picture.clone();
            }
            if refresh_token.scope.contains("email") {
                id_token_claims.email = Some(user.email.clone());
                id_token_claims.email_verified = Some(true);
            }

            // Add custom claims
            if let Some(custom_claims) = &user.claims {
                id_token_claims.additional_claims = custom_claims.clone();
            }
        }

        match jwt_manager.create_id_token(id_token_claims) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Failed to create ID token: {}", e);
                return Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: Some("Failed to create ID token".to_string()),
                    error_uri: None,
                })
                .into_response();
            }
        }
    } else {
        None
    };

    // Optionally create a new refresh token (token rotation)
    let new_refresh_token = match state
        .storage
        .create_refresh_token(client_id, &refresh_token.user_id, &refresh_token.scope)
        .await
    {
        Ok(token) => {
            // Revoke the old refresh token
            if let Err(e) = state.storage.revoke_refresh_token(refresh_token_str).await {
                warn!("Failed to revoke old refresh token: {}", e);
            }
            Some(token.token)
        }
        Err(e) => {
            error!("Failed to create new refresh token: {}", e);
            // Don't fail the request, just don't rotate the token
            None
        }
    };

    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        refresh_token: new_refresh_token,
        scope: refresh_token.scope,
    };

    Json(response).into_response()
}

// UserInfo endpoint
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    // Extract Bearer token from Authorization header
    let auth_header = match headers.get("authorization") {
        Some(header) => match header.to_str() {
            Ok(header_str) => header_str,
            Err(_) => {
                return Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: Some("Invalid authorization header".to_string()),
                    error_uri: None,
                })
                .into_response();
            }
        },
        None => {
            return Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: Some("Missing authorization header".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Check Bearer token format
    if !auth_header.starts_with("Bearer ") {
        return Json(ErrorResponse {
            error: "invalid_token".to_string(),
            error_description: Some("Invalid token type. Expected Bearer token".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    let access_token = &auth_header[7..]; // Remove "Bearer " prefix

    // Validate JWT token
    let jwt_manager = JwtManager::default();
    let token_claims = match jwt_manager.validate_access_token(access_token) {
        Ok(claims) => claims,
        Err(_) => {
            return Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: Some("Invalid or expired access token".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Check if token is expired
    let now = Utc::now().timestamp();
    if token_claims.exp < now {
        return Json(ErrorResponse {
            error: "invalid_token".to_string(),
            error_description: Some("Access token has expired".to_string()),
            error_uri: None,
        })
        .into_response();
    }

    // Get user information
    let user = match state.storage.get_user(&token_claims.sub) {
        Some(user) => user,
        None => {
            return Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: Some("User not found".to_string()),
                error_uri: None,
            })
            .into_response();
        }
    };

    // Build UserInfo response based on granted scopes
    let scopes: Vec<&str> = token_claims.scope.split_whitespace().collect();
    let mut userinfo = UserInfoResponse {
        sub: token_claims.sub.clone(),
        name: None,
        given_name: None,
        family_name: None,
        email: None,
        email_verified: None,
        picture: None,
        additional_claims: HashMap::new(),
    };

    // Add profile claims if profile scope is granted
    if scopes.contains(&"profile") {
        userinfo.name = Some(user.name.clone());
        userinfo.given_name = user.given_name.clone();
        userinfo.family_name = user.family_name.clone();
        userinfo.picture = user.picture.clone();
    }

    // Add email claims if email scope is granted
    if scopes.contains(&"email") {
        userinfo.email = Some(user.email.clone());
        userinfo.email_verified = Some(true); // For simplicity, all emails are verified
    }

    // Add custom claims if available
    if let Some(custom_claims) = &user.claims {
        userinfo.additional_claims = custom_claims.clone();
    }

    Json(userinfo).into_response()
}

// Logout endpoint
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(logout_params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    // Handle both POST form data and query parameters for logout
    let post_logout_redirect_uri = logout_params.get("post_logout_redirect_uri");
    let id_token_hint = logout_params.get("id_token_hint");
    let session_id = logout_params.get("session_id");

    // If we have an ID token hint, validate and extract session info
    if let Some(token) = id_token_hint {
        let jwt_manager = JwtManager::default();
        if let Ok(claims) = jwt_manager.validate_id_token(token) {
            // Token is valid, we could use claims.sub to identify the user
            info!("Logging out user: {}", claims.sub);
        }
    }

    // If we have a session ID, invalidate it
    if let Some(sid) = session_id {
        if let Err(e) = state.storage.delete_session(sid).await {
            warn!("Failed to delete session {}: {}", sid, e);
        } else {
            info!("Session {} invalidated", sid);
        }
    }

    // Check for Bearer token in Authorization header and revoke if present
    if let Some(auth_header) = headers.get("authorization")
        && let Ok(header_str) = auth_header.to_str()
        && let Some(access_token) = header_str.strip_prefix("Bearer ")
    {
        if let Err(e) = state.storage.revoke_access_token(access_token).await {
            warn!("Failed to revoke access token: {}", e);
        } else {
            info!("Access token revoked during logout");
        }
    }

    // Redirect to post logout URI if provided and valid
    if let Some(redirect_uri) = post_logout_redirect_uri {
        // Basic validation - in production you'd want more thorough validation
        if redirect_uri.starts_with("http://") || redirect_uri.starts_with("https://") {
            return Redirect::to(redirect_uri).into_response();
        }
    }

    // Default logout success page
    Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Logged Out - OIDC Rock</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .button { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px; }
        .button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h2>🔓 Successfully Logged Out</h2>
    <div class="success">
        <p>You have been logged out successfully from OIDC Rock.</p>
        <p>Your session and tokens have been invalidated.</p>
    </div>

    <p>
        <a href="/" class="button">🏠 Return to Home</a>
        <a href="/login" class="button">🔐 Login Again</a>
    </p>

    <p style="color: #666; font-size: 14px;">
        For security, please close your browser if you're on a shared computer.
    </p>
</body>
</html>
"#,
    ).into_response()
}

// JWKS endpoint
pub async fn jwks() -> impl IntoResponse {
    let jwt_manager = JwtManager::default();
    let jwks = jwt_manager.get_jwks();
    Json(jwks)
}

// Helper functions
fn create_error_response(error: &str, description: &str) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}

fn create_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Redirect {
    let mut redirect_url = format!(
        "{}?error={}&error_description={}",
        redirect_uri,
        urlencoding::encode(error),
        urlencoding::encode(description)
    );

    if let Some(state) = state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }

    Redirect::to(&redirect_url)
}
