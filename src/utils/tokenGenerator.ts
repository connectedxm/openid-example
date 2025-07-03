import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import keyManager from './keyManager';
import { User, IdTokenClaims } from '../types';

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  id_token?: string;
  refresh_token?: string;
}

export default class TokenGenerator {
  private issuer: string;
  private accessTokenExpiry = 3600; // 1 hour
  private idTokenExpiry = 3600; // 1 hour

  constructor(issuer: string) {
    this.issuer = issuer;
  }

  // Generate complete token response for OAuth/OIDC flow
  generateTokenResponse(
    clientId: string,
    scopes: string[],
    user?: User,
    nonce?: string
  ): TokenResponse {
    const isUserFlow = !!user;
    const accessToken = this.generateAccessToken(clientId, scopes, user);
    
    const response: TokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenExpiry,
      scope: scopes.join(' ')
    };

    // Generate ID token if openid scope is requested
    if (scopes.includes('openid')) {
      const idToken = this.generateIdToken(clientId, scopes, user, nonce);
      response.id_token = idToken;
    }

    // Add refresh token for user flows
    if (isUserFlow) {
      response.refresh_token = uuidv4();
    }

    return response;
  }

  // Generate JWT access token
  private generateAccessToken(clientId: string, scopes: string[], user?: User): string {
    const payload: any = {
      jti: uuidv4(),
      client_id: clientId,
      scope: scopes.join(' '),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.accessTokenExpiry,
      iss: this.issuer
    };

    // Add user subject for authorization code flow
    if (user) {
      payload.sub = user.sub;
    }

    return jwt.sign(payload, keyManager.getPrivateKey(), {
      algorithm: 'RS256',
      keyid: keyManager.getKid()
    });
  }

  // Generate JWT ID token with user claims based on scopes
  private generateIdToken(
    clientId: string,
    scopes: string[],
    user?: User,
    nonce?: string
  ): string {
    const now = Math.floor(Date.now() / 1000);
    
    const claims: IdTokenClaims = {
      iss: this.issuer,
      sub: user?.sub || clientId,
      aud: clientId,
      iat: now,
      exp: now + this.idTokenExpiry,
      auth_time: now
    };

    // Add nonce if provided (for security)
    if (nonce) {
      claims.nonce = nonce;
    }

    // Add user claims based on requested scopes
    if (user) {
      if (scopes.includes('email')) {
        claims.email = user.email;
      }

      if (scopes.includes('profile')) {
        claims.first_name = user.first_name;
        claims.last_name = user.last_name;
        claims.referenceId = user.referenceId;
      }
    }

    return jwt.sign(claims, keyManager.getPrivateKey(), {
      algorithm: 'RS256',
      keyid: keyManager.getKid()
    });
  }

  // Extract user information from access token for /userinfo endpoint
  getUserInfo(accessToken: string): any {
    try {
      const decoded = jwt.verify(accessToken, keyManager.getPublicKey(), {
        algorithms: ['RS256'],
        issuer: this.issuer
      }) as any;

      // For client credentials flow
      if (!decoded.sub || decoded.sub === decoded.client_id) {
        return {
          sub: decoded.client_id,
          client_id: decoded.client_id,
          scope: decoded.scope
        };
      }

      // For authorization code flow - find user by sub
      const users: User[] = require('../data/users.json');
      const user = users.find(u => u.sub === decoded.sub);
      
      if (!user) {
        throw new Error('User not found');
      }

      const userInfo: any = {
        sub: user.sub
      };

      const scopes = decoded.scope ? decoded.scope.split(' ') : [];

      if (scopes.includes('email')) {
        userInfo.email = user.email;
      }

      if (scopes.includes('profile')) {
        userInfo.first_name = user.first_name;
        userInfo.last_name = user.last_name;
        userInfo.referenceId = user.referenceId;
      }

      return userInfo;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }
} 