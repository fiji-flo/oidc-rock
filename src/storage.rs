use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::{Config, User};
use crate::crypto::{generate_random_string, hash_password, verify_password};
use crate::models::{AccessToken, AuthorizationCode, IdToken, RefreshToken, Session};

#[derive(Debug)]
pub struct InMemoryStorage {
    // User data
    users: HashMap<String, User>,

    // Session storage
    sessions: Arc<RwLock<HashMap<String, Session>>>,

    // Authorization codes
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,

    // Access tokens
    access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,

    // ID tokens
    id_tokens: Arc<RwLock<HashMap<String, IdToken>>>,

    // Refresh tokens
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,

    // Password hashes (for security, don't store plain passwords)
    password_hashes: HashMap<String, String>,
}

impl InMemoryStorage {
    pub fn new(config: &Config) -> Self {
        let mut users = HashMap::new();
        let mut password_hashes = HashMap::new();

        // Load users from config and hash their passwords
        for user in &config.users {
            users.insert(user.username.clone(), user.clone());
            password_hashes.insert(user.username.clone(), hash_password(&user.password));
        }

        Self {
            users,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            id_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            password_hashes,
        }
    }

    // User management
    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    pub fn verify_user_password(&self, username: &str, password: &str) -> bool {
        if let Some(hash) = self.password_hashes.get(username) {
            verify_password(password, hash)
        } else {
            false
        }
    }

    // Session management
    pub async fn create_session(&self, user_id: &str) -> Result<Session> {
        let session = Session {
            session_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24), // 24 hour session
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id.clone(), session.clone());

        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    pub async fn is_session_valid(&self, session_id: &str) -> bool {
        if let Some(session) = self.get_session(session_id).await {
            session.expires_at > Utc::now()
        } else {
            false
        }
    }

    // Authorization code management
    pub async fn create_authorization_code(
        &self,
        client_id: &str,
        user_id: &str,
        redirect_uri: &str,
        scope: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
    ) -> Result<AuthorizationCode> {
        let code = AuthorizationCode {
            code: generate_random_string(32),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            expires_at: Utc::now() + Duration::minutes(10), // 10 minute expiry
            code_challenge,
            code_challenge_method,
            nonce,
        };

        let mut codes = self.auth_codes.write().await;
        codes.insert(code.code.clone(), code.clone());

        Ok(code)
    }

    pub async fn get_authorization_code(&self, code: &str) -> Option<AuthorizationCode> {
        let codes = self.auth_codes.read().await;
        codes.get(code).cloned()
    }

    pub async fn consume_authorization_code(&self, code: &str) -> Result<AuthorizationCode> {
        let mut codes = self.auth_codes.write().await;
        codes
            .remove(code)
            .ok_or_else(|| anyhow!("Authorization code not found or already used"))
    }

    pub async fn is_authorization_code_valid(&self, code: &str) -> bool {
        if let Some(auth_code) = self.get_authorization_code(code).await {
            auth_code.expires_at > Utc::now()
        } else {
            false
        }
    }

    // Access token management
    pub async fn create_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
        expires_in_seconds: u64,
    ) -> Result<AccessToken> {
        let token = AccessToken {
            token: generate_random_string(64),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            scope: scope.to_string(),
            expires_at: Utc::now() + Duration::seconds(expires_in_seconds as i64),
            token_type: "Bearer".to_string(),
        };

        let mut tokens = self.access_tokens.write().await;
        tokens.insert(token.token.clone(), token.clone());

        Ok(token)
    }

    pub async fn get_access_token(&self, token: &str) -> Option<AccessToken> {
        let tokens = self.access_tokens.read().await;
        tokens.get(token).cloned()
    }

    pub async fn is_access_token_valid(&self, token: &str) -> bool {
        if let Some(access_token) = self.get_access_token(token).await {
            access_token.expires_at > Utc::now()
        } else {
            false
        }
    }

    pub async fn revoke_access_token(&self, token: &str) -> Result<()> {
        let mut tokens = self.access_tokens.write().await;
        tokens.remove(token);
        Ok(())
    }

    // ID token management
    pub async fn create_id_token(
        &self,
        client_id: &str,
        user_id: &str,
        expires_in_seconds: u64,
    ) -> Result<IdToken> {
        let token = IdToken {
            token: generate_random_string(64),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            expires_at: Utc::now() + Duration::seconds(expires_in_seconds as i64),
        };

        let mut tokens = self.id_tokens.write().await;
        tokens.insert(token.token.clone(), token.clone());

        Ok(token)
    }

    pub async fn get_id_token(&self, token: &str) -> Option<IdToken> {
        let tokens = self.id_tokens.read().await;
        tokens.get(token).cloned()
    }

    // Refresh token management
    pub async fn create_refresh_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
    ) -> Result<RefreshToken> {
        let token = RefreshToken {
            token: generate_random_string(64),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            scope: scope.to_string(),
            expires_at: Utc::now() + Duration::days(30), // 30 day refresh token
        };

        let mut tokens = self.refresh_tokens.write().await;
        tokens.insert(token.token.clone(), token.clone());

        Ok(token)
    }

    pub async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let tokens = self.refresh_tokens.read().await;
        tokens.get(token).cloned()
    }

    pub async fn is_refresh_token_valid(&self, token: &str) -> bool {
        if let Some(refresh_token) = self.get_refresh_token(token).await {
            refresh_token.expires_at > Utc::now()
        } else {
            false
        }
    }

    pub async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let mut tokens = self.refresh_tokens.write().await;
        tokens.remove(token);
        Ok(())
    }

    // Cleanup expired tokens/codes (should be called periodically)
    pub async fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();

        // Clean up sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| session.expires_at > now);
        }

        // Clean up authorization codes
        {
            let mut codes = self.auth_codes.write().await;
            codes.retain(|_, code| code.expires_at > now);
        }

        // Clean up access tokens
        {
            let mut tokens = self.access_tokens.write().await;
            tokens.retain(|_, token| token.expires_at > now);
        }

        // Clean up refresh tokens
        {
            let mut tokens = self.refresh_tokens.write().await;
            tokens.retain(|_, token| token.expires_at > now);
        }

        Ok(())
    }

    // Statistics for debugging
    pub async fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();

        stats.insert("users".to_string(), self.users.len());
        stats.insert("sessions".to_string(), self.sessions.read().await.len());
        stats.insert("auth_codes".to_string(), self.auth_codes.read().await.len());
        stats.insert(
            "access_tokens".to_string(),
            self.access_tokens.read().await.len(),
        );
        stats.insert("id_tokens".to_string(), self.id_tokens.read().await.len());
        stats.insert(
            "refresh_tokens".to_string(),
            self.refresh_tokens.read().await.len(),
        );

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_user_verification() {
        let config = Config::default();
        let storage = InMemoryStorage::new(&config);

        // Test valid user
        assert!(storage.verify_user_password("testuser", "password"));

        // Test invalid password
        assert!(!storage.verify_user_password("testuser", "wrongpassword"));

        // Test non-existent user
        assert!(!storage.verify_user_password("nonexistent", "password"));
    }

    #[tokio::test]
    async fn test_session_management() {
        let config = Config::default();
        let storage = InMemoryStorage::new(&config);

        // Create session
        let session = storage.create_session("testuser").await.unwrap();
        assert!(!session.session_id.is_empty());

        // Retrieve session
        let retrieved = storage.get_session(&session.session_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "testuser");

        // Check validity
        assert!(storage.is_session_valid(&session.session_id).await);

        // Delete session
        storage.delete_session(&session.session_id).await.unwrap();
        assert!(!storage.is_session_valid(&session.session_id).await);
    }

    #[tokio::test]
    async fn test_authorization_code_flow() {
        let config = Config::default();
        let storage = InMemoryStorage::new(&config);

        // Create authorization code
        let code = storage
            .create_authorization_code(
                "test-client",
                "testuser",
                "http://localhost:8080/callback",
                "openid profile",
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert!(!code.code.is_empty());
        assert!(storage.is_authorization_code_valid(&code.code).await);

        // Consume authorization code
        let consumed = storage
            .consume_authorization_code(&code.code)
            .await
            .unwrap();
        assert_eq!(consumed.client_id, "test-client");

        // Code should no longer be valid
        assert!(!storage.is_authorization_code_valid(&code.code).await);
    }

    #[tokio::test]
    async fn test_token_management() {
        let config = Config::default();
        let storage = InMemoryStorage::new(&config);

        // Create access token
        let access_token = storage
            .create_access_token("test-client", "testuser", "openid profile", 3600)
            .await
            .unwrap();

        assert!(storage.is_access_token_valid(&access_token.token).await);

        // Create refresh token
        let refresh_token = storage
            .create_refresh_token("test-client", "testuser", "openid profile")
            .await
            .unwrap();

        assert!(storage.is_refresh_token_valid(&refresh_token.token).await);

        // Revoke tokens
        storage
            .revoke_access_token(&access_token.token)
            .await
            .unwrap();
        storage
            .revoke_refresh_token(&refresh_token.token)
            .await
            .unwrap();

        assert!(!storage.is_access_token_valid(&access_token.token).await);
        assert!(!storage.is_refresh_token_valid(&refresh_token.token).await);
    }
}
