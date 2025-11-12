use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub oidc: OidcConfig,
    pub users: Vec<User>,
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub token_expiry_seconds: u64,
    pub supported_scopes: Vec<String>,
    pub supported_response_types: Vec<String>,
    pub supported_grant_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub email: String,
    pub name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub claims: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub response_types: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub client_name: Option<String>,
}

impl Config {
    pub async fn from_file(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn get_client(&self, client_id: &str) -> Option<&Client> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }

    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3080,
                base_url: "http://127.0.0.1:3080".to_string(),
            },
            oidc: OidcConfig {
                issuer: "http://127.0.0.1:3080".to_string(),
                token_expiry_seconds: 3600,
                supported_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                supported_response_types: vec!["code".to_string()],
                supported_grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
            },
            users: vec![User {
                username: "testuser".to_string(),
                password: "password".to_string(),
                email: "test@example.com".to_string(),
                name: "Test User".to_string(),
                given_name: Some("Test".to_string()),
                family_name: Some("User".to_string()),
                picture: None,
                claims: None,
            }],
            clients: vec![Client {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                redirect_uris: vec!["http://localhost:8080/callback".to_string()],
                response_types: vec!["code".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                client_name: Some("Test Client".to_string()),
            }],
        }
    }
}
