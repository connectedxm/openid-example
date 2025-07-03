// Client configuration
export interface Client {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  grant_types: string[];
}

// User data
export interface User {
  sub: string;
  email: string;
  password: string;
  email_verified: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  preferred_username: string;
  locale?: string;
  zoneinfo?: string;
  updated_at?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  birthdate?: string;
  gender?: string;
  website?: string;
  custom_department?: string;
  custom_employee_id?: string;
  custom_role?: string;
}

// Authorization code with PKCE support
export interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  expiresAt: Date;
  nonce?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

// Session data
export interface Session {
  sessionId: string;
  userId: string;
  expiresAt: Date;
}

// Token claims
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  preferred_username?: string;
  locale?: string;
  zoneinfo?: string;
  updated_at?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  birthdate?: string;
  gender?: string;
  website?: string;
  custom_department?: string;
  custom_employee_id?: string;
  custom_role?: string;
} 