# OIDC Rock - Simple OIDC Provider for Testing

A lightweight OpenID Connect (OIDC) provider built with Rust and Axum, designed for testing and development purposes. All data is stored in memory and configured via YAML files.

## Features

- ✅ OpenID Connect Discovery endpoint
- ✅ Authorization Code flow with nonce support
- ✅ PKCE (Proof Key for Code Exchange) - Both S256 and plain methods
- ✅ JWT ID tokens and Access tokens with comprehensive claims
- ✅ UserInfo endpoint with Bearer token authentication
- ✅ Refresh Token grant implementation
- ✅ Token Revocation endpoint (RFC 7009)
- ✅ RP-Initiated Logout with session management
- ✅ JWKS endpoint for key discovery
- ✅ In-memory storage with automatic cleanup
- ✅ YAML-based configuration
- ✅ Multiple users and clients support
- ✅ Custom claims support
- ✅ Simple web-based login interface with PKCE support
- ✅ CORS support for SPA testing
- ✅ Optional TLS/HTTPS support with rustls
- ✅ Comprehensive test suite with 21 integration tests
- ✅ PKCE helper utility for testing

## Quick Start

### 0. Generate Certs

Install [mkcert](https://github.com/FiloSottile/mkcert) and then:

```bash
mkdir .mkcert
mkcert -key-file ./mkcert/localhost.key.pem -cert-file ./mkcert/localhost/cert.pem localhost
```

### 1. Build and Run

```bash
cargo run config.yaml
```

Or build a release version:

```bash
cargo build --release
./target/release/oidc-rock config.yaml
```

### 2. Access the Provider

- **Home page**: http://127.0.0.1:3080/
- **Discovery endpoint**: http://127.0.0.1:3080/.well-known/openid-configuration
- **Login page**: http://127.0.0.1:3080/login

## Configuration

The provider is configured via a YAML file. See `config.yaml` for a complete example.

### Server Configuration

```yaml
server:
  host: "127.0.0.1"
  port: 3080
  base_url: "http://127.0.0.1:3080"
  # Optional TLS configuration
  tls:
    enabled: true
    cert_path: "certs/cert.pem"
    key_path: "certs/key.pem"
```

**TLS/HTTPS Support:**
- Set `tls.enabled: true` to enable HTTPS
- Provide paths to your certificate and private key files
- If `tls` is omitted or `enabled: false`, the server runs on HTTP
- For testing, you can generate self-signed certificates with:
  ```bash
  mkdir -p certs
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout certs/key.pem -out certs/cert.pem \
    -days 365 -subj "/CN=localhost"
  ```

### OIDC Configuration

```yaml
oidc:
  issuer: "http://127.0.0.1:3080"
  signing_key: "your-secret-signing-key-change-this"
  token_expiry_seconds: 3600
  supported_scopes:
    - "openid"
    - "profile"
    - "email"
    - "offline_access"
  supported_response_types:
    - "code"
  supported_grant_types:
    - "authorization_code"
    - "refresh_token"
```

### Users

```yaml
users:
  - username: "testuser"
    password: "password"
    email: "test@example.com"
    name: "Test User"
    given_name: "Test"
    family_name: "User"
    picture: "https://via.placeholder.com/150"
    claims:
      department: "Engineering"
      role: "Developer"
      employee_id: "12345"
```

### Clients

```yaml
clients:
  - client_id: "test-client"
    client_secret: "test-secret"
    client_name: "Test Application"
    redirect_uris:
      - "http://localhost:8080/callback"
    response_types:
      - "code"
    grant_types:
      - "authorization_code"
      - "refresh_token"
    scopes:
      - "openid"
      - "profile"
      - "email"
```

## OIDC Endpoints

| Endpoint | URL | Description |
|----------|-----|-------------|
| Discovery | `/.well-known/openid-configuration` | OIDC discovery document with PKCE methods |
| JWKS | `/.well-known/jwks.json` | JSON Web Key Set |
| Authorization | `/auth` | Authorization endpoint with PKCE support |
| Token | `/token` | Token exchange endpoint (authorization_code, refresh_token) |
| Revoke | `/revoke` | Token revocation endpoint (RFC 7009) |
| UserInfo | `/userinfo` | User information endpoint with Bearer auth |
| Logout | `/logout` | RP-Initiated Logout endpoint |
| Login | `/login` | Web login form with PKCE parameters |

## License

MIT License - feel free to use this for testing and development!

## Contributing

This is a simple test tool, but contributions are welcome! Please feel free to:

- Report bugs
- Suggest improvements
- Submit pull requests
- Add new features

## Troubleshooting

### Common Issues

1. **Port 3080 already in use**: Change the port in `config.yaml`
2. **Invalid redirect URI**: Make sure the redirect URI in your client matches exactly what's configured
3. **Token validation errors**: Check that the issuer URL matches your configuration
4. **CORS errors**: The provider includes permissive CORS headers, but check your client configuration

### Logging

The application uses tracing for logging. Set the log level with:

```bash
RUST_LOG=debug cargo run config.yaml
```

### Common OIDC Flow

1. Application redirects user to `/auth` with client_id, redirect_uri, etc.
2. User sees login form at `/login`
3. After successful login, user is redirected back with authorization code
4. Application exchanges code for tokens at `/token` endpoint
5. Application can get user info from `/userinfo` endpoint using access token

Happy testing! 🚀
