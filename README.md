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

## Testing with OAuth.tools

[OAuth.tools](https://oauth.tools/) is an excellent online tool for testing OAuth 2.0 and OpenID Connect flows. Here's how to use it to test your OIDC server:

### Step 1: Configure OAuth.tools

1. Go to [https://oauth.tools/](https://oauth.tools/)
2. Click on **"Authorization Code Flow"**
3. Fill in the following configuration:

**Basic Configuration:**
- **Authorization Endpoint**: `http://localhost:3000/authorize`
- **Token Endpoint**: `http://localhost:3000/token`
- **Client ID**: `connected-staging`
- **Client Secret**: `cognito-secret-123`
- **Redirect URI**: `https://oauth.tools/callback/code`
- **Scope**: `openid email profile`

**Advanced Configuration:**
- **PKCE**: Enable PKCE with **S256** method
- **Response Type**: `code`
- **Response Mode**: `query`

### Step 2: Update Client Configuration

Before testing, you need to add OAuth.tools callback URL to your client configuration:

```json
{
  "client_id": "connected-staging",
  "client_secret": "cognito-secret-123",
  "client_name": "AWS Cognito Client",
  "redirect_uris": [
    "https://connected-connected-auth.auth.us-east-1.amazoncognito.com/oauth2/idpresponse",
    "https://oauth.tools/callback/code"
  ],
  "allowed_scopes": ["openid", "email", "profile"],
  "grant_types": ["authorization_code"]
}
```

### Step 3: Test the Authorization Flow

1. **Start Authorization**: Click **"Start Authorization"** in OAuth.tools
2. **Login**: You'll be redirected to your login page. Use these test credentials:
   - **Email**: `john.doe@example.com`
   - **Password**: `password123`
3. **Get Authorization Code**: After login, you'll be redirected back to OAuth.tools with an authorization code
4. **Exchange for Tokens**: OAuth.tools will automatically exchange the code for tokens
5. **View Results**: You'll see the ID token, access token, and refresh token

### Step 4: Test Token Validation

1. **Copy the Access Token** from OAuth.tools
2. **Test UserInfo Endpoint**:
   ```bash
   curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
        http://localhost:3000/userinfo
   ```
3. **Decode ID Token**: Use [jwt.io](https://jwt.io) to decode and verify the ID token

### Step 5: Test Discovery Endpoint

1. **Get Discovery Document**:
   ```bash
   curl http://localhost:3000/.well-known/openid-configuration | jq
   ```

2. **Verify JWKS Endpoint**:
   ```bash
   curl http://localhost:3000/jwks | jq
   ```

## Configuration for Production Testing

### Using ngrok for Public Testing

If you want to test with a public URL (required for AWS Cognito integration):

1. **Install ngrok**: [https://ngrok.com/](https://ngrok.com/)
2. **Start your server**: `npm run dev`
3. **Expose with ngrok**: `ngrok http 3000`
4. **Update OAuth.tools configuration** with your ngrok URL:
   - **Authorization Endpoint**: `https://your-ngrok-url.ngrok.io/authorize`
   - **Token Endpoint**: `https://your-ngrok-url.ngrok.io/token`

### Environment Variables

Set these environment variables for production:

```bash
export ISSUER=https://your-domain.com
export NODE_ENV=production
export PORT=3000
```

## AWS Cognito Integration

### Step 1: Set up OIDC Provider in Cognito

1. Go to your Cognito User Pool in AWS Console
2. Navigate to **"Sign-in experience"** → **"Federated identity provider sign-in"**
3. Click **"Add identity provider"** → **"OpenID Connect"**
4. Configure:
   - **Provider name**: `TestOIDC` (or your choice)
   - **Client ID**: `connected-staging`
   - **Client secret**: `cognito-secret-123`
   - **Authorize scope**: `openid email profile`
   - **Issuer URL**: `https://your-domain.com` (your server URL)
   - **Discovery URL**: Will auto-populate from issuer

### Step 2: Test with OAuth.tools and Cognito

1. **Test Direct OIDC Flow** (OAuth.tools → Your Server):
   ```
   https://oauth.tools/ → https://your-server.com/authorize → Login → Tokens
   ```

2. **Test Cognito Integration** (OAuth.tools → Cognito → Your Server):
   ```
   https://oauth.tools/ → Cognito → Your Server → Login → Cognito → Tokens
   ```

### Step 3: Attribute Mapping

Map OIDC claims to Cognito attributes:
- `sub` → Username
- `email` → Email
- `email_verified` → Email Verified
- `given_name` → Given Name
- `family_name` → Family Name
- `name` → Name
- `picture` → Picture

## Test Users

Located in `src/data/users.json`:

| Email | Password | Name |
|-------|----------|------|
| john.doe@example.com | password123 | John Doe |
| jane.smith@example.com | password456 | Jane Smith |

## Test Clients

Located in `src/data/clients.json`:

**AWS Cognito Client:**
- Client ID: `connected-staging`
- Client Secret: `cognito-secret-123`
- Redirect URI: `https://connected-connected-auth.auth.us-east-1.amazoncognito.com/oauth2/idpresponse`

## Troubleshooting with OAuth.tools

### Common Issues and Solutions

#### 1. "Invalid redirect_uri" Error
**Problem**: OAuth.tools callback URL not registered
**Solution**: Add `https://oauth.tools/callback/code` to your client's `redirect_uris`

#### 2. "Invalid client" Error
**Problem**: Client ID/secret mismatch
**Solution**: Verify `connected-staging` and `cognito-secret-123` match exactly

#### 3. "Unsupported response type" Error
**Problem**: Wrong response type in OAuth.tools
**Solution**: Ensure OAuth.tools is set to `response_type=code`

#### 4. PKCE Errors
**Problem**: PKCE configuration mismatch
**Solution**: Enable PKCE with S256 method in OAuth.tools

#### 5. Token Validation Fails
**Problem**: JWT signature verification fails
**Solution**: Check JWKS endpoint is accessible at `/jwks`

### Testing Checklist

- [ ] Discovery endpoint returns valid configuration
- [ ] JWKS endpoint returns valid keys
- [ ] Authorization endpoint accepts valid requests
- [ ] Login page displays correctly
- [ ] Token endpoint returns valid tokens
- [ ] UserInfo endpoint returns user data
- [ ] Tokens are properly signed and verifiable
- [ ] PKCE flow works correctly
- [ ] All scopes are supported

## Advanced Testing Scenarios

### 1. Test Error Handling

**Invalid Client ID**:
```bash
curl "http://localhost:3000/authorize?client_id=invalid&redirect_uri=https://oauth.tools/callback/code&response_type=code"
```

**Invalid Redirect URI**:
```bash
curl "http://localhost:3000/authorize?client_id=connected-staging&redirect_uri=https://evil.com&response_type=code"
```

### 2. Test Token Expiration

1. Generate tokens with OAuth.tools
2. Wait for expiration (check `exp` claim in JWT)
3. Test expired token with UserInfo endpoint

### 3. Test PKCE Flow

1. Generate code verifier and challenge
2. Use OAuth.tools PKCE feature
3. Verify code challenge validation

## Deployment

### 🚀 Railway

1. Push your code to GitHub
2. Go to [railway.app](https://railway.app) and sign up
3. Click "Deploy from GitHub repo"
4. Select this repository
5. Set environment variable: `ISSUER=https://your-railway-domain.railway.app`

### 🌐 Render

1. Connect your GitHub repository
2. Set build command: `npm run build`
3. Set start command: `npm start`
4. Set environment variable: `ISSUER=https://your-app.onrender.com`

## Security Considerations

⚠️ **This is a test implementation** and should not be used in production without additional security measures:

- Use proper HTTPS certificates
- Implement rate limiting
- Use a persistent database for sessions and codes
- Add proper CSRF protection
- Implement secure password policies
- Add multi-factor authentication
- Use production-grade key management

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

## License

MIT 