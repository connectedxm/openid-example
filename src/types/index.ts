// User interface for authentication
export interface User {
  sub: string;
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  referenceId: string;
}

// Client configuration
export interface Client {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  grant_types: string[];
}

// Session management
export interface Session {
  sessionId: string;
  userId: string;
  expiresAt: Date;
}

// ID Token claims structure
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time: number;
  nonce?: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  referenceId?: string;
}

// Authorization code (simplified without PKCE)
export interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  expiresAt: Date;
  nonce?: string;
  state?: string;
} 