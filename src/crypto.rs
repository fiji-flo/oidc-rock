use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::models::{AccessTokenClaims, IdTokenClaims};

static PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcM8Xyj3/3kNgt
YA134d5fziWVqYr4xfU3dZJXIrcUEGLoP8ESN8g3raQacjNNKUvfCOhR70qpfSCX
glh7LKA8kCK9uttP5CalRcdNUaPqJix1n1QB411y/lbAq7NeJBk9Qkfhnc36jIzO
a4SunONvcXZ3gKFnZqpcvlK2gvCm79A86frmTfl0qH4QK2BqPZxWNgg/UBc14qyH
CDRXYBYHvYHuIHOOR6IYg1ykBHD6AvCk7mmge4wjUqOgNKCWD0TFjUadKLmqWcUr
ExuRR09GJZv0IJau859TXVgZ8M5gO67K8s6iysw7C8+DuixvNn3dz03HyKuxEJIp
QMuhA829AgMBAAECggEAHZTG7sLgSf2nTNEufgBVw0EKQ4S3KpxNSNn+gr4jIgrh
fpmx8iSUPQaSmQrmYWM+0gN8UiV3PjWU/0V/ZWylSf2C7UIA3Eal+mXZVEW3Y2kl
Z9ezjV1h3GTWeqOWQPtQeK5CwchVN2dSMxi2hk6FLx9q7rrU8/MSx8q5idMlSQeG
XRf+HbJk/Y6K0JI0u5hIZXJtZWPOubk638mX3CTqxVjtL3NkwTRDoAq4hr+HLf6y
ZhPz8AVoArD4htOlRAt/0rEePyvxLd+OyVcBpw1RPkVLM99sOV8F5M2WNnZaZGnK
+I2jC6bgxxD/ZxtaHSmeNwrulxULT2W4u/7yGdeGgQKBgQDduLoRcAODj/1k432d
4Mz/oYsyKtnzouwzzYPt3zoa3MqFOGL2V/N6jd9uALbWm+0bQWJofI56GcAKCF3y
bU3bfot2aP3QyVP53JWUO671Sbqq5WHAkGvc1ioIcQNGGsOg/jBk3gVOYWxU7nCS
sGr0JTpH59ysRkrVyTUJKOE7lQKBgQD+PunqdbHIW+aFt9+AxNhckXWZfMHamkqp
xzpP1wkNIU3eV4L6k+3kp2rOnBcdDnliVcD7ynGp77kfH68/joFT7cT0mcJz0Uyb
tZsZ03kr8F0skyWm/YUbH3gUVwdUFW1fCGi/zRcDUXzc3NrWVAeSipsj0wWiAba6
WRObmTx/iQKBgQClrf/8P8Ogb9xdo1CexPjqnIAzQKoU0M3H9+55tbDpmcsLuZLZ
mecq0REAVjBKNcH79+PdSBX/T3adCJuLJ/ph5jG4jcP8XDUQJLDxT5fxWuLOCRH+
nuy63J4UKL7Vh/JfPxJSjUVRyKL25CXit0l0nszqJmxTn0MUdYHYEmAb8QKBgADk
a6G9BAC2AdsaSBiFmFTK1eTSAUQpInXyEwxQruFy6nkLSZRjjIQu6jsLZTFe6aIk
tuarUTbNdpLbY5wPffizbuuE1p/dbi1lt8OhcF1tHIaZhZpObXco5xz7KTVsVdPt
jaCOsbP7RzrnM4VpChXDksPPa8ejxeZlhaIYKZQxAoGBAMzv+rOUR9YcC2DBFWVz
NqZ3ehHYhCJhdB//aGNukjVWRtgv05CYKJHfPa4xZiFfJATqWWLgYrBArOWoEm49
+0Sot4Ll4j410LY2hsgoxTSCpIQ6sXZ4+30u59tVVTOh7LUPTuQMql1HZBA0dyAC
HzzXpwszWDulMimwGKFDsF3w
-----END PRIVATE KEY-----
"#;

static PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3DPF8o9/95DYLWANd+He
X84llamK+MX1N3WSVyK3FBBi6D/BEjfIN62kGnIzTSlL3wjoUe9KqX0gl4JYeyyg
PJAivbrbT+QmpUXHTVGj6iYsdZ9UAeNdcv5WwKuzXiQZPUJH4Z3N+oyMzmuErpzj
b3F2d4ChZ2aqXL5StoLwpu/QPOn65k35dKh+ECtgaj2cVjYIP1AXNeKshwg0V2AW
B72B7iBzjkeiGINcpARw+gLwpO5poHuMI1KjoDSglg9ExY1GnSi5qlnFKxMbkUdP
RiWb9CCWrvOfU11YGfDOYDuuyvLOosrMOwvPg7osbzZ93c9Nx8irsRCSKUDLoQPN
vQIDAQAB
-----END PUBLIC KEY-----
"#;
static KID: &str = "058358c1-edcb-4b4e-9f2a-4f86914c84de";

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl Default for JwtManager {
    fn default() -> Self {
        Self {
            encoding_key: EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
            decoding_key: DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).unwrap(),
        }
    }
}

impl JwtManager {
    pub fn create_id_token(&self, claims: IdTokenClaims) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to create ID token: {}", e))
    }

    pub fn create_access_token(&self, claims: AccessTokenClaims) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to create access token: {}", e))
    }

    pub fn validate_id_token(&self, token: &str) -> Result<IdTokenClaims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.required_spec_claims = HashSet::new(); // Don't require standard claims for flexibility
        validation.validate_aud = false;

        let token_data = decode::<IdTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Failed to validate ID token: {}", e))?;

        Ok(token_data.claims)
    }

    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.required_spec_claims = HashSet::new();
        validation.validate_aud = false;

        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Failed to validate access token: {}", e))?;

        Ok(token_data.claims)
    }
}

pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

pub fn verify_code_challenge(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let computed_challenge = generate_code_challenge(verifier);
            computed_challenge == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}

pub fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    format!("{:x}", hash)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let computed_hash = hash_password(password);
    computed_hash == hash
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Value>,
}

impl JwtManager {
    pub fn get_jwks(&self) -> JwkSet {
        // For simplicity, we'll return an empty JWK set since we're using HMAC
        // In a real implementation with RSA/EC keys, you'd expose the public key here
        JwkSet {
            keys: vec![
                json!({"kty":"RSA","e":"AQAB","kid":KID,"n":"3DPF8o9_95DYLWANd-HeX84llamK-MX1N3WSVyK3FBBi6D_BEjfIN62kGnIzTSlL3wjoUe9KqX0gl4JYeyygPJAivbrbT-QmpUXHTVGj6iYsdZ9UAeNdcv5WwKuzXiQZPUJH4Z3N-oyMzmuErpzjb3F2d4ChZ2aqXL5StoLwpu_QPOn65k35dKh-ECtgaj2cVjYIP1AXNeKshwg0V2AWB72B7iBzjkeiGINcpARw-gLwpO5poHuMI1KjoDSglg9ExY1GnSi5qlnFKxMbkUdPRiWb9CCWrvOfU11YGfDOYDuuyvLOosrMOwvPg7osbzZ93c9Nx8irsRCSKUDLoQPNvQ"}),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_jwt_creation_and_validation() {
        let manager = JwtManager::default();

        let id_claims = IdTokenClaims {
            iss: "test-issuer".to_string(),
            sub: "test-user".to_string(),
            aud: "test-client".to_string(),
            exp: (Utc::now().timestamp() + 3600),
            iat: Utc::now().timestamp(),
            auth_time: None,
            nonce: None,
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            picture: None,
            additional_claims: HashMap::new(),
        };

        let token = manager.create_id_token(id_claims.clone()).unwrap();
        let decoded = manager.validate_id_token(&token).unwrap();

        assert_eq!(decoded.sub, id_claims.sub);
        assert_eq!(decoded.aud, id_claims.aud);
    }

    #[test]
    fn test_code_challenge() {
        let verifier = "test-verifier";
        let challenge = generate_code_challenge(verifier);

        assert!(verify_code_challenge(verifier, &challenge, "S256"));
        assert!(!verify_code_challenge("wrong-verifier", &challenge, "S256"));
    }

    #[test]
    fn test_password_hashing() {
        let password = "test-password";
        let hash = hash_password(password);

        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn test_random_string_generation() {
        let s1 = generate_random_string(32);
        let s2 = generate_random_string(32);

        assert_eq!(s1.len(), 32);
        assert_eq!(s2.len(), 32);
        assert_ne!(s1, s2); // Very unlikely to be the same
    }
}
