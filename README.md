# OIDC Rock - Simple OIDC Provider for Testing

A lightweight OpenID Connect (OIDC) provider built with Rust and Axum, designed for testing and development purposes. All data is stored in memory and configured via YAML files.

## Features

- ✅ OpenID Connect Discovery endpoint
- ✅ Authorization Code flow with nonce support
- ✅ JWT ID tokens and Access tokens with comprehensive claims
- ✅ UserInfo endpoint with Bearer token authentication
- ✅ Refresh Token grant implementation
- ✅ RP-Initiated Logout with session management
- ✅ JWKS endpoint for key discovery
- ✅ In-memory storage with automatic cleanup
- ✅ YAML-based configuration
- ✅ Multiple users and clients support
- ✅ Custom claims support
- ✅ Simple web-based login interface
- ✅ CORS support for SPA testing
- ✅ Comprehensive test suite with 16 integration tests

## Quick Start

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
| Discovery | `/.well-known/openid-configuration` | OIDC discovery document |
| JWKS | `/.well-known/jwks.json` | JSON Web Key Set |
| Authorization | `/auth` | Authorization endpoint for login |
| Token | `/token` | Token exchange endpoint (authorization_code, refresh_token) |
| UserInfo | `/userinfo` | User information endpoint with Bearer auth |
| Logout | `/logout` | RP-Initiated Logout endpoint |
| Login | `/login` | Web login form (testing only) |

## Testing the Provider

### Using curl

1. **Get Discovery Document**:
```bash
curl http://127.0.0.1:3080/.well-known/openid-configuration | jq
```

2. **Start Authorization Flow**:
```bash
# Open in browser or use curl to get redirect
curl -v "http://127.0.0.1:3080/auth?client_id=test-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20profile%20email&state=test-state"
```

3. **Exchange Code for Tokens**:
```bash
curl -X POST http://127.0.0.1:3080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=http://localhost:8080/callback&client_id=test-client&client_secret=test-secret"

4. **Get User Information**:
```bash
curl http://127.0.0.1:3080/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

5. **Refresh Tokens**:
```bash
curl -X POST http://127.0.0.1:3080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=test-client&client_secret=test-secret"
```

### Integration with Applications

The provider works with any OIDC-compatible application. Here are some common configurations:

#### For Web Applications
- **Issuer**: `http://127.0.0.1:3080`
- **Client ID**: `test-client`
- **Client Secret**: `test-secret`
- **Redirect URI**: `http://localhost:8080/callback`

#### For SPAs (Single Page Applications)
- **Issuer**: `http://127.0.0.1:3080`
- **Client ID**: `spa-client`
- **No Client Secret** (public client)
- **Redirect URI**: `http://localhost:3080/callback`

## Default Test Data

### Users
| Username | Password | Email | Name |
|----------|----------|-------|------|
| testuser | password | test@example.com | Test User |
| alice | alice123 | alice@example.com | Alice Johnson |
| bob | bob123 | bob@example.com | Bob Smith |

### Clients
| Client ID | Client Secret | Redirect URI |
|-----------|---------------|--------------|
| test-client | test-secret | http://localhost:8080/callback |
| spa-client | (none) | http://localhost:3080/callback |
| mobile-app | mobile-secret-key | myapp://auth/callback |

## Security Notes

⚠️ **This is a test provider only!** Do not use in production:

- Passwords are stored in plaintext in the config file
- Simple HMAC-based JWT signing
- No rate limiting or security hardening
- In-memory storage (data lost on restart)
- Basic session management

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run only unit tests
cargo test --lib

# Run integration tests
cargo test --test integration_tests
```

### Project Structure

```
src/
├── main.rs          # Application entry point
├── config.rs        # YAML configuration handling
├── crypto.rs        # JWT and cryptographic utilities
├── handlers.rs      # HTTP request handlers
├── models.rs        # Data models and structures
└── storage.rs       # In-memory storage implementation
```

### Adding Features

The codebase is designed to be easily extensible:

- Add new endpoints in `handlers.rs`
- Extend configuration in `config.rs`  
- Add new token types or claims in `models.rs`
- Enhance storage capabilities in `storage.rs`

### Current Implementation Status

✅ **All TODOs Completed**: The implementation includes all major OIDC features:
- Full UserInfo endpoint with Bearer token validation
- Complete refresh token grant implementation  
- Nonce handling throughout the authorization flow
- Comprehensive logout with session management
- JWKS endpoint for key discovery
- Automatic token cleanup and maintenance
- 16 comprehensive integration tests

See `IMPLEMENTATION.md` for detailed implementation notes.

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