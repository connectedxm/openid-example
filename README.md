# OpenID Connect Provider

A simple OpenID Connect provider for demonstrating AWS Cognito integration.

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the server:**
   ```bash
   npm run dev
   ```

3. **Access the provider:**
   - Server: `http://localhost:3000`
   - Discovery: `http://localhost:3000/.well-known/openid-configuration`

## Demo Users

- **Email:** `john.doe@example.com` | **Password:** `password123`
- **Email:** `jane.smith@example.com` | **Password:** `password456`

## AWS Cognito Setup

1. **Create Identity Provider:**
   - Provider type: OpenID Connect
   - Provider URL: `https://your-domain.com`
   - Client ID: `connected-staging`
   - Client secret: `connected-staging-secret-123`

2. **Attribute Mapping:**
   - `sub` → `sub`
   - `email` → `email`
   - `first_name` → `given_name`
   - `last_name` → `family_name`
   - `referenceId` → `custom:referenceId`

## User Data Structure

Each user contains only essential fields:
- `sub` - Unique user identifier
- `email` - User's email address
- `first_name` - User's first name
- `last_name` - User's last name
- `referenceId` - Custom reference identifier

## Key Features

- ✅ OpenID Connect Discovery
- ✅ Authorization Code Flow
- ✅ JWT ID Tokens
- ✅ UserInfo Endpoint
- ✅ Session Management
- ✅ Simple & Clean Codebase

## Endpoints

- `/.well-known/openid-configuration` - Discovery document
- `/authorize` - Authorization endpoint
- `/token` - Token endpoint
- `/userinfo` - UserInfo endpoint
- `/jwks` - JSON Web Key Set
- `/health` - Health check

## Deployment

Deploy to any platform that supports Node.js:

```bash
npm run build
npm start
```

The server automatically detects Railway deployments and configures HTTPS accordingly. 