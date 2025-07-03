# OpenID Connect Provider for AWS Cognito Testing

A complete OpenID Connect (OIDC) provider implementation for testing AWS Cognito User Pool integrations. This server supports the Authorization Code flow with PKCE, making it suitable for user authentication scenarios.

## Features

- ✅ **Authorization Code Flow** with PKCE support
- ✅ **OpenID Connect Discovery** endpoint
- ✅ **JWT-signed tokens** (ID tokens and access tokens)
- ✅ **User authentication** with login page
- ✅ **Multiple test users and clients**
- ✅ **AWS Cognito compatible**
- ✅ **Session management**
- ✅ **Standard OIDC scopes** (openid, email, profile)

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Run the Server

```bash
# Development mode with hot reload
npm run dev

# Production mode
npm run build
npm start
```

The server will start on `http://localhost:3000` by default.

### 3. Test the Server

```bash
# Check health
curl http://localhost:3000/health

# Get OIDC discovery document
curl http://localhost:3000/.well-known/openid-configuration
```

## Configuration

### Test Users

Located in `src/data/users.json`:

| Email | Password | Name |
|-------|----------|------|
| john.doe@example.com | password123 | John Doe |
| jane.smith@example.com | password456 | Jane Smith |

### Test Clients

Located in `src/data/clients.json`:

**Generic Test Client:**
- Client ID: `test-client-1`
- Client Secret: `test-secret-1`
- Redirect URIs: `http://localhost:3000/callback`, `https://myapp.example.com/callback`

**AWS Cognito Client:**
- Client ID: `cognito-client`
- Client Secret: `cognito-secret-123`
- Redirect URI: `https://your-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/idpresponse`

## Authorization Code Flow

### 1. Authorization Request

Direct the user to:
```
http://localhost:3000/authorize?
  client_id=test-client-1&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid email profile&
  state=xyz&
  nonce=abc
```

With PKCE:
```
http://localhost:3000/authorize?
  client_id=test-client-1&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid email profile&
  state=xyz&
  nonce=abc&
  code_challenge=XXXXXXXXXX&
  code_challenge_method=S256
```

### 2. User Login

The user will see a login page and can authenticate with one of the test users.

### 3. Authorization Code

After successful login, the user is redirected to:
```
http://localhost:3000/callback?code=AUTH_CODE&state=xyz
```

### 4. Token Exchange

Exchange the authorization code for tokens:

```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=test-client-1" \
  -d "client_secret=test-secret-1"
```

With PKCE:
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=test-client-1" \
  -d "client_secret=test-secret-1" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

### 5. Get User Info

```bash
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## AWS Cognito Integration

### 1. Set up OIDC Provider in Cognito

1. Go to your Cognito User Pool in AWS Console
2. Navigate to "Sign-in experience" → "Federated identity provider sign-in"
3. Click "Add identity provider" → "OpenID Connect"
4. Configure:
   - **Provider name**: `TestOIDC` (or your choice)
   - **Client ID**: `cognito-client`
   - **Client secret**: `cognito-secret-123`
   - **Authorize scope**: `openid email profile`
   - **Issuer URL**: `http://localhost:3000` (or your deployed URL)
   - **Discovery URL**: Will auto-populate from issuer

### 2. Attribute Mapping

Map OIDC claims to Cognito attributes:
- `sub` → Username
- `email` → Email
- `email_verified` → Email Verified
- `given_name` → Given Name
- `family_name` → Family Name
- `name` → Name
- `picture` → Picture

### 3. Enable for App Client

1. Go to "App integration" → "App clients"
2. Select your app client
3. Edit "Hosted UI settings"
4. Under "Identity providers", enable your OIDC provider
5. Save changes

### 4. Update Redirect URI

Update `src/data/clients.json` with your actual Cognito domain:
```json
{
  "client_id": "cognito-client",
  "redirect_uris": [
    "https://YOUR-DOMAIN.auth.REGION.amazoncognito.com/oauth2/idpresponse"
  ]
}
```

## Deployment

### 🚀 Railway

1. Push your code to GitHub
2. Go to [railway.app](https://railway.app) and sign up
3. Click "Deploy from GitHub repo"
4. Select this repository
5. Railway auto-detects the Dockerfile and deploys!

**Cost**: $5/month or free tier with 500 hours  
**Benefits**: Automatic HTTPS, Git-based deployments, built-in monitoring

### Environment Variables

- `PORT` - Server port (default: 3000)
- `ISSUER` - Issuer URL (default: `http://localhost:3000`)
- `NODE_ENV` - Environment (development/production)

## Project Structure

```
src/
├── data/
│   ├── clients.json    # Client configurations
│   └── users.json      # Test users
├── stores/
│   └── authStore.ts    # In-memory auth code & session storage
├── types/
│   └── index.ts        # TypeScript interfaces
├── utils/
│   ├── keyManager.ts   # RSA key management
│   ├── pkce.ts         # PKCE utilities
│   └── tokenGenerator.ts # JWT token generation
├── views/
│   └── login.html      # Login page
└── server.ts           # Main server application
```

## Security Considerations

⚠️ **This is a test implementation** and should not be used in production. For production use:

- Use proper HTTPS certificates
- Implement rate limiting
- Use a persistent database for sessions and codes
- Add proper CSRF protection
- Implement secure password policies
- Add multi-factor authentication
- Use production-grade key management

## Troubleshooting

### "Invalid client" error
- Ensure the client_id and client_secret match those in `clients.json`
- Check that the redirect_uri exactly matches the registered URI

### "Invalid grant" error
- Authorization codes expire after 10 minutes
- Codes are single-use only
- Ensure PKCE verifier matches the challenge

### Token validation fails
- Check that the JWKS endpoint is accessible
- Verify the issuer URL matches in all configurations

## License

MIT 