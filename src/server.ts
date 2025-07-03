import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { Client, User } from './types';
import clients from './data/clients.json';
import users from './data/users.json';
import TokenGenerator from './utils/tokenGenerator';
import keyManager from './utils/keyManager';
import authStore from './stores/authStore';
import { generateAuthorizationCode, verifyCodeChallenge } from './utils/pkce';

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const ISSUER = process.env.RAILWAY_PUBLIC_DOMAIN || `http://localhost:${PORT}`;

// Initialize token generator
const tokenGenerator = new TokenGenerator(ISSUER);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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

// Discovery endpoint
app.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  const config = {
    issuer: ISSUER,
    authorization_endpoint: `https://${ISSUER}/authorize`,
    token_endpoint: `https://${ISSUER}/token`,
    userinfo_endpoint: `https://${ISSUER}/userinfo`,
    jwks_uri: `https://${ISSUER}/jwks`,
    end_session_endpoint: `https://${ISSUER}/logout`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    userinfo_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: ['openid', 'email', 'profile'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
      'email', 'email_verified', 'name', 'given_name',
      'family_name', 'picture', 'preferred_username'
    ],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    claims_parameter_supported: false
  };

  res.json(config);
  return;
});

// JWKS endpoint
app.get('/jwks', async (req: Request, res: Response) => {
  try {
    const jwks = await keyManager.getJWKS();
    res.json(jwks);
    return;
  } catch (error) {
    console.error('Error generating JWKS:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to generate JWKS'
    });
    return;
  }
});

// Authorization endpoint - GET (display login page)
app.get('/authorize', (req: Request, res: Response) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method
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

  // Validate response type
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
      // User already logged in, generate code and redirect
      const authCode = generateAuthorizationCode();
      authStore.saveAuthCode({
        code: authCode,
        clientId: client_id as string,
        userId: session.userId,
        redirectUri: redirect_uri as string,
        scope: scope as string || 'openid',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        nonce: nonce as string,
        state: state as string,
        codeChallenge: code_challenge as string,
        codeChallengeMethod: code_challenge_method as string === 'S256' ? 'S256' : 'S256'
      });

      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('code', authCode);
      if (state) redirectUrl.searchParams.set('state', state as string);
      
      res.redirect(redirectUrl.toString());
      return;
    }
  }

  // No session, show login page
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
  return;
});

// Authorization endpoint - POST (handle login)
app.post('/authorize', (req: Request, res: Response) => {
  const { email, password } = req.body;
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method
  } = req.query;

  // Authenticate user
  const user = authenticateUser(email, password);
  if (!user) {
    // Redirect back to login with error
    const loginUrl = new URL(`https://${ISSUER}/authorize`);
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
  const authCode = generateAuthorizationCode();
  authStore.saveAuthCode({
    code: authCode,
    clientId: client_id as string,
    userId: user.sub,
    redirectUri: redirect_uri as string,
    scope: scope as string || 'openid',
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    nonce: nonce as string,
    state: state as string,
    codeChallenge: code_challenge as string,
    codeChallengeMethod: code_challenge_method as string === 'S256' ? 'S256' : 'S256'
  });

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state as string);

  res.redirect(redirectUrl.toString());
  return;
});

// Token endpoint
app.post('/token', (req: Request, res: Response) => {
  const { 
    grant_type, 
    client_id, 
    client_secret, 
    code, 
    redirect_uri,
    code_verifier,
    scope 
  } = req.body;

  // Only support client_secret_post method as required by AWS Cognito
  const clientId = client_id;
  const clientSecret = client_secret;

  // AWS Cognito requires client_secret_post, not client_secret_basic
  if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Only client_secret_post authentication method is supported'
    });
    return;
  }

  // Handle authorization code grant
  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
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

    // Validate PKCE if code challenge was used
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Code verifier required'
        });
        return;
      }

      const validPKCE = verifyCodeChallenge(
        code_verifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod || 'S256'
      );

      if (!validPKCE) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid code verifier'
        });
        return;
        }
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

  // Handle refresh token grant
  if (grant_type === 'refresh_token') {
    // TODO: Implement refresh token grant if needed
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Refresh token grant not implemented'
    });
    return;
  }

  // Unsupported grant type
  res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Grant type not supported'
  });
  return;
});

// Userinfo endpoint
app.get('/userinfo', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
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
    return;
  } catch (error) {
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
    return;
  }
});

// Logout endpoint (optional but useful)
app.get('/logout', (req: Request, res: Response) => {
  const sessionId = req.cookies?.session;
  if (sessionId) {
    authStore.deleteSession(sessionId);
    res.clearCookie('session');
  }
  
  const { redirect_uri } = req.query;
  if (redirect_uri) {
    res.redirect(redirect_uri as string);
    return;
  } else {
    res.send('Logged out successfully');
    return;
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'ok', 
    issuer: ISSUER,
    endpoints: {
      discovery: '/.well-known/openid-configuration',
      jwks: '/jwks',
      authorization: '/authorize',
      token: '/token',
      userinfo: '/userinfo'
    }
  });
  return;
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'server_error',
    error_description: 'An internal server error occurred'
  });
  return;
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 OpenID Connect Provider running at https://${ISSUER}`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`   Discovery: https://${ISSUER}/.well-known/openid-configuration`);
  console.log(`   JWKS:      https://${ISSUER}/jwks`);
  console.log(`   Authorize: https://${ISSUER}/authorize`);
  console.log(`   Token:     https://${ISSUER}/token`);
  console.log(`   UserInfo:  https://${ISSUER}/userinfo`);
  console.log(`   Health:    https://${ISSUER}/health`);
  console.log(`\n🔐 Test Clients:`);
  console.log(`   Client ID: test-client-1`);
  console.log(`   Client Secret: test-secret-1`);
  console.log(`\n   AWS Cognito Client ID: cognito-client`);
  console.log(`   AWS Cognito Client Secret: cognito-secret-123`);
}); 