# OpenID Connect Provider Demo

A minimal OpenID Connect provider that demonstrates how OAuth 2.0 Authorization Code flow works with AWS Cognito. This is an educational example showing the core concepts of an OAuth server.

## What This Demonstrates

This server implements the **OAuth 2.0 Authorization Code flow** with **OpenID Connect** extensions. It shows how:

1. **Clients discover OAuth endpoints** via the discovery document
2. **Users authenticate** through a login page
3. **Authorization codes** are generated and exchanged for tokens
4. **JWT tokens** contain user claims for identity
5. **Sessions** maintain user login state

## The OAuth Flow

```
1. Client redirects user to: /authorize?client_id=...&redirect_uri=...
2. User sees login page and enters credentials
3. Credentials POST to: /login (not part of OAuth spec)
4. Server validates user and creates authorization code
5. User redirected back to client with: ?code=abc123
6. Client exchanges code for tokens at: /token
7. Client can get user info from: /userinfo
```

## Core Endpoints

### **Discovery Document**
`GET /.well-known/openid-configuration`

Tells clients where to find all OAuth endpoints and what features are supported.

```json
{
  "issuer": "https://your-domain.com",
  "authorization_endpoint": "https://your-domain.com/authorize",
  "token_endpoint": "https://your-domain.com/token",
  "userinfo_endpoint": "https://your-domain.com/userinfo",
  "jwks_uri": "https://your-domain.com/jwks",
  "scopes_supported": ["openid", "email", "profile"],
  "claims_supported": ["sub", "email", "first_name", "last_name", "referenceId"]
}
```

### **Authorization Endpoint**
`GET /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid`

- **Purpose**: Start the OAuth flow
- **What it does**: Shows login page or redirects with authorization code
- **Parameters**: 
  - `client_id` - Identifies the requesting application
  - `redirect_uri` - Where to send user after authorization
  - `response_type` - Always "code" for authorization code flow
  - `scope` - Requested permissions (openid, email, profile)
  - `state` - Security parameter to prevent CSRF attacks

### **Token Endpoint**
`POST /token`

- **Purpose**: Exchange authorization code for access token and ID token
- **Authentication**: Client credentials (ID + secret)
- **Parameters**:
  - `grant_type=authorization_code`
  - `code` - The authorization code from /authorize
  - `redirect_uri` - Must match the original redirect URI
  - `client_id` - Client identifier
  - `client_secret` - Client secret for authentication

**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "scope": "openid email profile"
}
```

### **UserInfo Endpoint**
`GET /userinfo`

- **Purpose**: Get user information using access token
- **Authentication**: Bearer token in Authorization header
- **Returns**: User claims based on granted scopes

```json
{
  "sub": "user-123456",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "referenceId": "REF001"
}
```

### **JWKS Endpoint**
`GET /jwks`

- **Purpose**: Provide public keys for JWT signature verification
- **Used by**: Clients to verify ID token signatures
- **Format**: JSON Web Key Set (JWKS)

### **Login Endpoint** (Implementation Detail)
`POST /login`

- **Purpose**: Process user login credentials (not part of OAuth spec)
- **Used by**: Login form on the authorization page
- **Parameters**: `email`, `password` in request body, OAuth params in query string
- **Note**: This is an implementation detail - OAuth doesn't specify how authentication happens

## Key Concepts Demonstrated

### **Authorization Codes**
- **Temporary secrets** (10-minute expiration)
- **Single-use only** - consumed when exchanged for tokens
- **Cryptographically secure** - 64-character hex strings
- **Client-specific** - tied to specific client and redirect URI

### **JWT Tokens**
- **ID Token**: Contains user identity claims (who the user is)
- **Access Token**: Used to access protected resources
- **Signed with RS256** - clients can verify authenticity
- **Claims based on scopes** - only requested data is included

### **Session Management**
- **HTTP-only cookies** - prevent XSS attacks
- **1-hour expiration** - automatic cleanup
- **Server-side storage** - sessions stored in memory

### **Client Authentication**
- **Client credentials required** - All clients must provide ID and secret
- **Multiple methods** - POST body or HTTP Basic authentication  
- **Confidential clients only** - No public client support
- **Redirect URI validation** - prevents authorization code theft

## User Data Structure

Simplified to essential fields only:

```json
{
  "sub": "user-123456",
  "email": "john.doe@example.com", 
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe",
  "referenceId": "REF001"
}
```

## AWS Cognito Integration

When used as a Cognito identity provider:

1. **Cognito Configuration**:
   - Provider type: OpenID Connect
   - Provider URL: Your server's base URL
   - Client ID: `connected-staging`
   - Client secret: `connected-staging-secret-123`

2. **Attribute Mapping**:
   - `sub` → `sub` (required)
   - `email` → `email`
   - `first_name` → `given_name`
   - `last_name` → `family_name`
   - `referenceId` → `custom:referenceId`

3. **Flow**: Cognito redirects users to your `/authorize` endpoint, handles the OAuth flow, and maps the returned claims to Cognito user attributes.

## Demo Users

Two test users are included:
- `john.doe@example.com` / `password123`
- `jane.smith@example.com` / `password456`

## Security Features

- **CSRF protection** via `state` parameter
- **Secure session cookies** (httpOnly, sameSite)
- **JWT signature verification** using RS256
- **Client authentication** for token exchange
- **Authorization code expiration** (10 minutes)
- **Redirect URI validation** prevents code theft

## Running the Demo

```bash
npm install
npm run dev
# Server starts at http://localhost:3000
```

Visit the discovery document at `http://localhost:3000/.well-known/openid-configuration` to see all available endpoints and capabilities. 