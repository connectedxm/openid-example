import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { Client, User } from './types';
import clients from './data/clients.json';
import users from './data/users.json';
import TokenGenerator from './utils/tokenGenerator';
import keyManager from './utils/keyManager';
import authStore from './stores/authStore';
import crypto from 'crypto';

const app = express();

// Configuration
const PROTOCOL = process.env.RAILWAY_PUBLIC_DOMAIN ? 'https' : 'http';
const PORT = parseInt(process.env.PORT || '3000', 10);
const ISSUER = process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`;
const FULL_ISSUER = `${PROTOCOL}://${ISSUER}`;

// Initialize token generator
const tokenGenerator = new TokenGenerator(FULL_ISSUER);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Simple request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Helper functions
function authenticateClient(clientId: string, clientSecret?: string): Client | undefined {
  const client = clients.find((c: Client) => c.client_id === clientId);
  if (!client) return undefined;
  
  // For public clients or when secret not required
  if (!clientSecret) return client;
  
  // Verify secret for confidential clients
  return client.client_secret === clientSecret ? client : undefined;
}

function authenticateUser(email: string, password: string): User | undefined {
  return users.find((u: User) => u.email === email && u.password === password);
}

function parseScopes(scopeString: string): string[] {
  return scopeString ? scopeString.split(' ').filter(s => s.length > 0) : [];
}

// OpenID Connect Discovery Document
// This tells clients where to find all the OAuth/OIDC endpoints
app.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  const config = {
    issuer: FULL_ISSUER,
    authorization_endpoint: `${FULL_ISSUER}/authorize`,
    token_endpoint: `${FULL_ISSUER}/token`,
    userinfo_endpoint: `${FULL_ISSUER}/userinfo`,
    jwks_uri: `${FULL_ISSUER}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    scopes_supported: ['openid', 'email', 'profile'],
    claims_supported: ['sub', 'email', 'first_name', 'last_name', 'referenceId'],
    grant_types_supported: ['authorization_code']
  };

  res.json(config);
});

// JSON Web Key Set (JWKS) endpoint
// Provides public keys for verifying JWT signatures
app.get('/jwks', async (req: Request, res: Response) => {
  try {
    const jwks = await keyManager.getJWKS();
    res.json(jwks);
  } catch (error) {
    console.error('Error generating JWKS:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to generate JWKS'
    });
  }
});

// Authorization endpoint - GET (display login page)
// This is where the OAuth flow begins
app.get('/authorize', (req: Request, res: Response) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    nonce
  } = req.query;

  // Validate required parameters
  if (!client_id || !redirect_uri || !response_type) {
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required parameters'
    });
    return;
  }

  // Validate client
  const client = clients.find((c: Client) => c.client_id === client_id);
  if (!client) {
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client'
    });
    return;
  }

  // Validate redirect URI
  if (!client.redirect_uris.includes(redirect_uri as string)) {
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid redirect_uri'
    });
    return;
  }

  // Validate response type (only authorization code flow supported)
  if (response_type !== 'code') {
    res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported'
    });
    return;
  }

  // Check for existing session
  const sessionId = req.cookies?.session;
  if (sessionId) {
    const session = authStore.getSession(sessionId);
    if (session) {
      // User already logged in, generate authorization code and redirect
      const authCode = crypto.randomBytes(32).toString('hex');
      authStore.saveAuthCode({
        code: authCode,
        clientId: client_id as string,
        userId: session.userId,
        redirectUri: redirect_uri as string,
        scope: scope as string || 'openid',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        nonce: nonce as string,
        state: state as string
      });

      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('code', authCode);
      if (state) redirectUrl.searchParams.set('state', state as string);
      
      res.redirect(redirectUrl.toString());
      return;
    }
  }

  // No session, show login page
  res.sendFile(path.join(__dirname, '..', 'src', 'views', 'login.html'));
});

// Authorization endpoint - POST (handle login)
// Processes user login and generates authorization code
app.post('/login', (req: Request, res: Response) => {
  const { email, password } = req.body;
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    nonce
  } = req.query;

  // Authenticate user
  const user = authenticateUser(email, password);
  if (!user) {
    // Redirect back to login with error
    const loginUrl = new URL(`${FULL_ISSUER}/authorize`);
    Object.entries(req.query).forEach(([key, value]) => {
      if (value) loginUrl.searchParams.set(key, value as string);
    });
    loginUrl.searchParams.set('error', 'invalid_credentials');
    res.redirect(loginUrl.toString());
    return;
  }

  // Create session
  const sessionId = authStore.createSession(user.sub);
  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000 // 1 hour
  });

  // Generate authorization code
  const authCode = crypto.randomBytes(32).toString('hex');
  authStore.saveAuthCode({
    code: authCode,
    clientId: client_id as string,
    userId: user.sub,
    redirectUri: redirect_uri as string,
    scope: scope as string || 'openid',
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    nonce: nonce as string,
    state: state as string
  });

  // Redirect back to client with authorization code
  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state as string);

  res.redirect(redirectUrl.toString());
});

// Token endpoint
// Exchanges authorization code for access token and ID token
app.post('/token', (req: Request, res: Response) => {
  const { 
    grant_type, 
    client_id, 
    client_secret, 
    code, 
    redirect_uri
  } = req.body;

  // Support both client_secret_post and client_secret_basic authentication methods
  let clientId = client_id;
  let clientSecret = client_secret;

  // Handle HTTP Basic authentication
  if (req.headers.authorization?.startsWith('Basic ')) {
    try {
      const credentials = Buffer.from(req.headers.authorization.slice(6), 'base64').toString('utf-8');
      const [basicClientId, basicClientSecret] = credentials.split(':');
      clientId = basicClientId;
      clientSecret = basicClientSecret;
    } catch (error) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid Basic authentication header'
      });
      return;
    }
  }

  if (!clientId) {
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
    return;
  }

  // Handle authorization code grant
  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters, code and redirect_uri are required'
      });
      return;
    }

    // Get and validate authorization code
    const authCode = authStore.consumeAuthCode(code);
    if (!authCode) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
      return;
    }

    // Validate client
    const client = authenticateClient(clientId, clientSecret);
    if (!client || client.client_id !== authCode.clientId) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      });
      return;
    }

    // Validate redirect URI
    if (authCode.redirectUri !== redirect_uri) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch'
      });
      return;
    }

    // Get user
    const user = users.find((u: User) => u.sub === authCode.userId);
    if (!user) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'User not found'
      });
      return;
    }

    // Generate tokens
    const scopes = parseScopes(authCode.scope);
    const tokenResponse = tokenGenerator.generateTokenResponse(
      clientId,
      scopes,
      user,
      authCode.nonce
    );

    res.json(tokenResponse);
    return;
  }

  // Unsupported grant type
  res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Grant type not supported'
  });
});

// UserInfo endpoint
// Returns user information based on the access token
app.get('/userinfo', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token required'
    });
    return;
  }

  const accessToken = authHeader.slice(7);

  try {
    const userInfo = tokenGenerator.getUserInfo(accessToken);
    res.json(userInfo);
  } catch (error) {
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
  }
});

// Logout endpoint
app.get('/logout', (req: Request, res: Response) => {
  const sessionId = req.cookies?.session;
  if (sessionId) {
    authStore.deleteSession(sessionId);
    res.clearCookie('session');
  }
  
  const { redirect_uri } = req.query;
  if (redirect_uri) {
    res.redirect(redirect_uri as string);
  } else {
    res.send('Logged out successfully');
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'ok', 
    issuer: FULL_ISSUER,
    endpoints: {
      discovery: '/.well-known/openid-configuration',
      jwks: '/jwks',
      authorization: '/authorize',
      token: '/token',
      userinfo: '/userinfo'
    }
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Server error:', err.message);
  res.status(500).json({
    error: 'server_error',
    error_description: 'An internal server error occurred'
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🚀 OpenID Connect Provider Started
Server: ${FULL_ISSUER}
Port: ${PORT}

📋 Endpoints:
  Discovery: ${FULL_ISSUER}/.well-known/openid-configuration
  JWKS:      ${FULL_ISSUER}/jwks
  Authorize: ${FULL_ISSUER}/authorize
  Token:     ${FULL_ISSUER}/token
  UserInfo:  ${FULL_ISSUER}/userinfo
  Health:    ${FULL_ISSUER}/health

🔐 Demo Users:
  Email: john.doe@example.com | Password: password123
  Email: jane.smith@example.com | Password: password456

🎯 Ready for AWS Cognito integration!
  `);
}); 