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

const PROTOCOL = process.env.NODE_ENV === 'production' ? 'https' : 'http';
const PORT = parseInt(process.env.PORT || '3000', 10);
const ISSUER = process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`;

// Initialize token generator
const tokenGenerator = new TokenGenerator(ISSUER);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const userAgent = req.get('User-Agent') || 'unknown';
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  console.log(`[${timestamp}] ${method} ${url} - IP: ${ip} - User-Agent: ${userAgent}`);
  
  // Log request body for POST requests (but redact sensitive data)
  if (method === 'POST' && req.body) {
    const sanitizedBody = { ...req.body };
    if (sanitizedBody.password) sanitizedBody.password = '[REDACTED]';
    if (sanitizedBody.client_secret) sanitizedBody.client_secret = '[REDACTED]';
    if (sanitizedBody.code_verifier) sanitizedBody.code_verifier = '[REDACTED]';
    console.log(`[${timestamp}] Request Body:`, sanitizedBody);
  }
  
  // Log query parameters
  if (Object.keys(req.query).length > 0) {
    const sanitizedQuery = { ...req.query };
    if (sanitizedQuery.code) sanitizedQuery.code = '[REDACTED]';
    console.log(`[${timestamp}] Query Params:`, sanitizedQuery);
  }
  
  // Log response
  const originalSend = res.send;
  res.send = function(data) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Response: ${res.statusCode} ${res.statusMessage || ''}`);
    if (res.statusCode >= 400) {
      console.log(`[${timestamp}] Error Response Body:`, typeof data === 'string' ? data : JSON.stringify(data));
    }
    return originalSend.call(this, data);
  };
  
  next();
});

// Helper functions
function authenticateClient(clientId: string, clientSecret?: string): Client | undefined {
  console.log(`[AUTH] Attempting to authenticate client: ${clientId}`);
  console.log(`[AUTH] Client secret provided: ${clientSecret ? 'YES' : 'NO'}`);
  
  const client = clients.find((c: Client) => c.client_id === clientId);
  if (!client) {
    console.error(`[AUTH] ❌ Client not found: ${clientId}`);
    console.error(`[AUTH] Available clients: ${clients.map(c => c.client_id).join(', ')}`);
    return undefined;
  }
  
  console.log(`[AUTH] ✅ Client found: ${client.client_name} (${client.client_id})`);
  
  // For public clients or when secret not required
  if (!clientSecret) {
    console.log(`[AUTH] ✅ No client secret required, returning client`);
    return client;
  }
  
  // Verify secret for confidential clients
  const isValidSecret = client.client_secret === clientSecret;
  if (!isValidSecret) {
    console.error(`[AUTH] ❌ Invalid client secret for client: ${clientId}`);
    console.error(`[AUTH] Expected secret length: ${client.client_secret?.length || 0}`);
    console.error(`[AUTH] Provided secret length: ${clientSecret.length}`);
  } else {
    console.log(`[AUTH] ✅ Client secret validated successfully`);
  }
  
  return isValidSecret ? client : undefined;
}

function authenticateUser(email: string, password: string): User | undefined {
  console.log(`[USER_AUTH] Attempting to authenticate user: ${email}`);
  
  const user = users.find((u: User) => u.email === email && u.password === password);
  if (!user) {
    console.error(`[USER_AUTH] ❌ User authentication failed for: ${email}`);
    console.log(`[USER_AUTH] Available users: ${users.map(u => u.email).join(', ')}`);
  } else {
    console.log(`[USER_AUTH] ✅ User authenticated successfully: ${user.name} (${user.sub})`);
  }
  
  return user;
}

function parseScopes(scopeString: string): string[] {
  return scopeString ? scopeString.split(' ').filter(s => s.length > 0) : [];
}

// Discovery endpoint
app.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
  
  const config = {
    issuer: `${PROTOCOL}://${ISSUER}`,
    authorization_endpoint: `${PROTOCOL}://${ISSUER}/authorize`,
    token_endpoint: `${PROTOCOL}://${ISSUER}/token`,
    userinfo_endpoint: `${PROTOCOL}://${ISSUER}/userinfo`,
    jwks_uri: `${PROTOCOL}://${ISSUER}/jwks`,
    end_session_endpoint: `${PROTOCOL}://${ISSUER}/logout`,
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
  console.log(`[JWKS] JWKS requested`);
  
  try {
    const jwks = await keyManager.getJWKS();
    console.log(`[JWKS] ✅ Generated JWKS with ${jwks.keys.length} keys`);
    res.json(jwks);
    return;
  } catch (error) {
    console.error(`[JWKS] ❌ Error generating JWKS:`, error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to generate JWKS'
    });
    return;
  }
});

// Authorization endpoint - GET (display login page)
app.get('/authorize', (req: Request, res: Response) => {
  console.log(`[AUTHORIZE] Authorization request received`);
  
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

  console.log(`[AUTHORIZE] Parameters: client_id=${client_id}, redirect_uri=${redirect_uri}, response_type=${response_type}`);
  console.log(`[AUTHORIZE] Scope: ${scope}, State: ${state}, Nonce: ${nonce ? 'provided' : 'not provided'}`);
  console.log(`[AUTHORIZE] PKCE: code_challenge=${code_challenge ? 'provided' : 'not provided'}, method=${code_challenge_method}`);

  // Validate required parameters
  if (!client_id || !redirect_uri || !response_type) {
    console.error(`[AUTHORIZE] ❌ Missing required parameters`);
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required parameters'
    });
    return;
  }

  // Validate client
  console.log(`[AUTHORIZE] Validating client: ${client_id}`);
  const client = clients.find((c: Client) => c.client_id === client_id);
  if (!client) {
    console.error(`[AUTHORIZE] ❌ Unknown client: ${client_id}`);
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client'
    });
    return;
  }
  console.log(`[AUTHORIZE] ✅ Client validated: ${client.client_name}`);

  // Validate redirect URI
  console.log(`[AUTHORIZE] Validating redirect URI: ${redirect_uri}`);
  console.log(`[AUTHORIZE] Allowed redirect URIs: ${client.redirect_uris.join(', ')}`);
  if (!client.redirect_uris.includes(redirect_uri as string)) {
    console.error(`[AUTHORIZE] ❌ Invalid redirect_uri: ${redirect_uri}`);
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid redirect_uri'
    });
    return;
  }
  console.log(`[AUTHORIZE] ✅ Redirect URI validated`);

  // Validate response type
  console.log(`[AUTHORIZE] Validating response type: ${response_type}`);
  if (response_type !== 'code') {
    console.error(`[AUTHORIZE] ❌ Unsupported response type: ${response_type}`);
    res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported'
    });
    return;
  }
  console.log(`[AUTHORIZE] ✅ Response type validated`);

  // Check for existing session
  const sessionId = req.cookies?.session;
  console.log(`[AUTHORIZE] Checking for existing session: ${sessionId ? 'found' : 'not found'}`);
  
  if (sessionId) {
    const session = authStore.getSession(sessionId);
    if (session) {
      console.log(`[AUTHORIZE] ✅ Valid session found for user: ${session.userId}`);
      console.log(`[AUTHORIZE] Generating authorization code and redirecting`);
      
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

      console.log(`[AUTHORIZE] ✅ Authorization code generated and saved`);
      
      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('code', authCode);
      if (state) redirectUrl.searchParams.set('state', state as string);
      
      console.log(`[AUTHORIZE] ✅ Redirecting to: ${redirectUrl.toString()}`);
      res.redirect(redirectUrl.toString());
      return;
    } else {
      console.log(`[AUTHORIZE] Session ID found but session invalid/expired`);
    }
  }

  // No session, show login page
  console.log(`[AUTHORIZE] No valid session, showing login page`);
  res.sendFile(path.join(__dirname, '..', 'src', 'views', 'login.html'));
  return;
});

// Authorization endpoint - POST (handle login)
app.post('/authorize', (req: Request, res: Response) => {
  console.log(`[LOGIN] Login attempt received`);
  
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

  console.log(`[LOGIN] Login attempt for: ${email}`);
  console.log(`[LOGIN] Client ID: ${client_id}`);

  // Authenticate user
  const user = authenticateUser(email, password);
  if (!user) {
    console.error(`[LOGIN] ❌ Login failed for: ${email}`);
    
    // Redirect back to login with error
    const loginUrl = new URL(`${PROTOCOL}://${ISSUER}/authorize`);
    Object.entries(req.query).forEach(([key, value]) => {
      if (value) loginUrl.searchParams.set(key, value as string);
    });
    loginUrl.searchParams.set('error', 'invalid_credentials');
    
    console.log(`[LOGIN] Redirecting back to login with error: ${loginUrl.toString()}`);
    res.redirect(loginUrl.toString());
    return;
  }
  
  console.log(`[LOGIN] ✅ Login successful for: ${user.name} (${user.sub})`);

  // Create session
  console.log(`[LOGIN] Creating session for user: ${user.sub}`);
  const sessionId = authStore.createSession(user.sub);
  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000 // 1 hour
  });
  console.log(`[LOGIN] ✅ Session created: ${sessionId}`);

  // Generate authorization code
  console.log(`[LOGIN] Generating authorization code`);
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
  console.log(`[LOGIN] ✅ Authorization code generated and saved`);

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state as string);

  console.log(`[LOGIN] ✅ Redirecting to client: ${redirectUrl.toString()}`);
  res.redirect(redirectUrl.toString());
  return;
});

// Token endpoint
app.post('/token', (req: Request, res: Response) => {
  console.log(`[TOKEN] Token request received`);
  
  const { 
    grant_type, 
    client_id, 
    client_secret, 
    code, 
    redirect_uri,
    code_verifier,
    scope 
  } = req.body;

  console.log(`[TOKEN] Grant type: ${grant_type}`);
  console.log(`[TOKEN] Client ID: ${client_id}`);
  console.log(`[TOKEN] Client secret provided: ${client_secret ? 'YES' : 'NO'}`);
  console.log(`[TOKEN] Authorization code provided: ${code ? 'YES' : 'NO'}`);
  console.log(`[TOKEN] Redirect URI: ${redirect_uri}`);
  console.log(`[TOKEN] Code verifier provided: ${code_verifier ? 'YES' : 'NO'}`);
  console.log(`[TOKEN] Scope: ${scope}`);

  // Only support client_secret_post method as required by AWS Cognito
  const clientId = client_id;
  const clientSecret = client_secret;

  // Validate client credentials are provided
  if (!clientId) {
    console.error(`[TOKEN] ❌ client_id is required`);
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
    return;
  }

  // AWS Cognito requires client_secret_post, not client_secret_basic
  if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
    console.error(`[TOKEN] ❌ Basic authentication not supported`);
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Only client_secret_post authentication method is supported'
    });
    return;
  }

  // Handle authorization code grant
  if (grant_type === 'authorization_code') {
    console.log(`[TOKEN] Processing authorization code grant`);
    
    if (!code || !redirect_uri) {
      console.error(`[TOKEN] ❌ Missing required parameters: code=${!!code}, redirect_uri=${!!redirect_uri}`);
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
      return;
    }

    // Get and validate authorization code
    console.log(`[TOKEN] Looking up authorization code`);
    const authCode = authStore.consumeAuthCode(code);
    if (!authCode) {
      console.error(`[TOKEN] ❌ Invalid or expired authorization code`);
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
      return;
    }
    
    console.log(`[TOKEN] ✅ Authorization code found and consumed`);
    console.log(`[TOKEN] Auth code details: clientId=${authCode.clientId}, userId=${authCode.userId}, scope=${authCode.scope}`);

    // Validate client
    console.log(`[TOKEN] Validating client authentication`);
    const client = authenticateClient(clientId, clientSecret);
    if (!client || client.client_id !== authCode.clientId) {
      console.error(`[TOKEN] ❌ Client authentication failed`);
      console.error(`[TOKEN] Provided client ID: ${clientId}`);
      console.error(`[TOKEN] Auth code client ID: ${authCode.clientId}`);
      console.error(`[TOKEN] Client found: ${!!client}`);
      console.error(`[TOKEN] Client ID match: ${client?.client_id === authCode.clientId}`);
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      });
      return;
    }
    
    console.log(`[TOKEN] ✅ Client authentication successful`);

    // Validate redirect URI
    console.log(`[TOKEN] Validating redirect URI`);
    console.log(`[TOKEN] Auth code redirect URI: ${authCode.redirectUri}`);
    console.log(`[TOKEN] Provided redirect URI: ${redirect_uri}`);
    if (authCode.redirectUri !== redirect_uri) {
      console.error(`[TOKEN] ❌ Redirect URI mismatch`);
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch'
      });
      return;
    }
    console.log(`[TOKEN] ✅ Redirect URI validated`);

    // Validate PKCE if code challenge was used
    if (authCode.codeChallenge) {
      console.log(`[TOKEN] Validating PKCE`);
      console.log(`[TOKEN] Code challenge method: ${authCode.codeChallengeMethod}`);
      
      if (!code_verifier) {
        console.error(`[TOKEN] ❌ Code verifier required but not provided`);
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
        console.error(`[TOKEN] ❌ Invalid code verifier`);
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid code verifier'
        });
        return;
      }
      
      console.log(`[TOKEN] ✅ PKCE validation successful`);
    } else {
      console.log(`[TOKEN] No PKCE validation required`);
    }

    // Get user
    console.log(`[TOKEN] Looking up user: ${authCode.userId}`);
    const user = users.find((u: User) => u.sub === authCode.userId);
    if (!user) {
      console.error(`[TOKEN] ❌ User not found: ${authCode.userId}`);
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'User not found'
      });
      return;
    }
    
    console.log(`[TOKEN] ✅ User found: ${user.name} (${user.sub})`);

    // Generate tokens
    console.log(`[TOKEN] Generating tokens`);
    const scopes = parseScopes(authCode.scope);
    console.log(`[TOKEN] Parsed scopes: ${scopes.join(', ')}`);
    
    const tokenResponse = tokenGenerator.generateTokenResponse(
      clientId,
      scopes,
      user,
      authCode.nonce
    );

    console.log(`[TOKEN] ✅ Token response generated successfully`);
    console.log(`[TOKEN] Response includes: access_token=${!!tokenResponse.access_token}, id_token=${!!tokenResponse.id_token}, refresh_token=${!!tokenResponse.refresh_token}`);
    
    res.json(tokenResponse);
    return;
  }

  // Handle refresh token grant
  if (grant_type === 'refresh_token') {
    console.log(`[TOKEN] Refresh token grant requested (not implemented)`);
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Refresh token grant not implemented'
    });
    return;
  }

  // Unsupported grant type
  console.error(`[TOKEN] ❌ Unsupported grant type: ${grant_type}`);
  res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Grant type not supported'
  });
  return;
});

// Userinfo endpoint
app.get('/userinfo', (req: Request, res: Response) => {
  console.log(`[USERINFO] UserInfo request received`);
  
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error(`[USERINFO] ❌ No valid authorization header`);
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token required'
    });
    return;
  }

  const accessToken = authHeader.slice(7);
  console.log(`[USERINFO] Access token provided: ${accessToken.substring(0, 20)}...`);

  try {
    const userInfo = tokenGenerator.getUserInfo(accessToken);
    console.log(`[USERINFO] ✅ UserInfo retrieved for subject: ${userInfo.sub}`);
    res.json(userInfo);
    return;
  } catch (error) {
    console.error(`[USERINFO] ❌ Invalid or expired access token:`, error);
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
    return;
  }
});

// Logout endpoint (optional but useful)
app.get('/logout', (req: Request, res: Response) => {
  console.log(`[LOGOUT] Logout request received`);
  
  const sessionId = req.cookies?.session;
  if (sessionId) {
    console.log(`[LOGOUT] Deleting session: ${sessionId}`);
    authStore.deleteSession(sessionId);
    res.clearCookie('session');
    console.log(`[LOGOUT] ✅ Session deleted and cookie cleared`);
  } else {
    console.log(`[LOGOUT] No session found to delete`);
  }
  
  const { redirect_uri } = req.query;
  if (redirect_uri) {
    console.log(`[LOGOUT] Redirecting to: ${redirect_uri}`);
    res.redirect(redirect_uri as string);
    return;
  } else {
    console.log(`[LOGOUT] ✅ Logout completed, no redirect`);
    res.send('Logged out successfully');
    return;
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  console.log(`[HEALTH] Health check requested`);
  
  const baseUrl = `${PROTOCOL}://${ISSUER}`;
  
  res.json({ 
    status: 'ok', 
    issuer: ISSUER,
    baseUrl: baseUrl,
    endpoints: {
      discovery: '/.well-known/openid-configuration',
      jwks: '/jwks',
      authorization: '/authorize',
      token: '/token',
      userinfo: '/userinfo'
    },
    clients: clients.map(c => ({
      client_id: c.client_id,
      client_name: c.client_name,
      redirect_uris: c.redirect_uris
    }))
  });
  
  console.log(`[HEALTH] ✅ Health check response sent`);
  return;
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  const timestamp = new Date().toISOString();
  console.error(`[ERROR] ${timestamp} - Unhandled error:`, err.stack);
  console.error(`[ERROR] Request: ${req.method} ${req.url}`);
  console.error(`[ERROR] User-Agent: ${req.get('User-Agent')}`);
  
  res.status(500).json({
    error: 'server_error',
    error_description: 'An internal server error occurred'
  });
  return;
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  const baseUrl = `${PROTOCOL}://${ISSUER}`;
  
  console.log(`
╔════════════════════════════════════════════════════════════════════════════════════════╗
║                            🚀 OpenID Connect Provider Started                           ║
╠════════════════════════════════════════════════════════════════════════════════════════╣
║ Server URL: ${baseUrl.padEnd(72)} ║
║ Environment: ${(process.env.NODE_ENV || 'development').padEnd(69)} ║
║ Port: ${PORT.toString().padEnd(80)} ║
║ Issuer: ${ISSUER.padEnd(78)} ║
╚════════════════════════════════════════════════════════════════════════════════════════╝
  `);
  
  console.log(`📋 Available endpoints:`);
  console.log(`   Discovery: ${baseUrl}/.well-known/openid-configuration`);
  console.log(`   JWKS:      ${baseUrl}/jwks`);
  console.log(`   Authorize: ${baseUrl}/authorize`);
  console.log(`   Token:     ${baseUrl}/token`);
  console.log(`   UserInfo:  ${baseUrl}/userinfo`);
  console.log(`   Health:    ${baseUrl}/health`);
  console.log(`   Logout:    ${baseUrl}/logout`);
  
  console.log(`\n🔐 Configured Clients (${clients.length}):`);
  clients.forEach((client: Client, index) => {
    console.log(`   ${index + 1}. ${client.client_name}`);
    console.log(`      Client ID: ${client.client_id}`);
    console.log(`      Client Secret: ${client.client_secret || 'N/A (public client)'}`);
    console.log(`      Grant Types: ${client.grant_types.join(', ')}`);
    console.log(`      Allowed Scopes: ${client.allowed_scopes.join(', ')}`);
    console.log(`      Redirect URIs:`);
    client.redirect_uris.forEach(uri => {
      console.log(`        - ${uri}`);
    });
    console.log('');
  });
  
  console.log(`👥 Demo Users (${users.length}):`);
  users.forEach((user: User, index) => {
    console.log(`   ${index + 1}. ${user.name} (${user.email})`);
    console.log(`      Subject: ${user.sub}`);
    console.log(`      Password: ${user.password}`);
    console.log('');
  });
  
  console.log(`🔧 Debug Features:`);
  console.log(`   - Comprehensive request/response logging`);
  console.log(`   - Client authentication debugging`);
  console.log(`   - PKCE verification logging`);
  console.log(`   - Session management logging`);
  console.log(`   - Token generation/validation logging`);
  
  console.log(`\n✅ Server ready to accept requests!`);
  console.log(`📊 Use the /health endpoint to verify server status`);
  console.log(`🔍 All requests will be logged with detailed information`);
}); 