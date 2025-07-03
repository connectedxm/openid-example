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
  private accessTokenExpiry: number = 3600; // 1 hour
  private idTokenExpiry: number = 3600; // 1 hour

  constructor(issuer: string) {
    this.issuer = issuer;
  }

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

    // Add nonce if provided
    if (nonce) {
      claims.nonce = nonce;
    }

    // Add user claims based on requested scopes
    if (user) {
      if (scopes.includes('email')) {
        claims.email = user.email;
        claims.email_verified = user.email_verified;
      }

      if (scopes.includes('profile')) {
        claims.name = user.name;
        claims.given_name = user.given_name;
        claims.family_name = user.family_name;
        claims.picture = user.picture;
        claims.preferred_username = user.preferred_username;
        
        // Add additional profile fields
        if (user.locale) claims.locale = user.locale;
        if (user.zoneinfo) claims.zoneinfo = user.zoneinfo;
        if (user.updated_at) claims.updated_at = user.updated_at;
        if (user.birthdate) claims.birthdate = user.birthdate;
        if (user.gender) claims.gender = user.gender;
        if (user.website) claims.website = user.website;
      }

      // Add phone claims if available (phone scope or profile scope)
      if (scopes.includes('phone') || scopes.includes('profile')) {
        if (user.phone_number) claims.phone_number = user.phone_number;
        if (user.phone_number_verified !== undefined) claims.phone_number_verified = user.phone_number_verified;
      }

      // Add address claims if available (address scope or profile scope)
      if (scopes.includes('address') || scopes.includes('profile')) {
        if (user.address) claims.address = user.address;
      }

      // Add custom claims (always include for easier Cognito mapping)
      if (user.custom_department) claims.custom_department = user.custom_department;
      if (user.custom_employee_id) claims.custom_employee_id = user.custom_employee_id;
      if (user.custom_role) claims.custom_role = user.custom_role;
    }

    return jwt.sign(claims, keyManager.getPrivateKey(), {
      algorithm: 'RS256',
      keyid: keyManager.getKid()
    });
  }

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
        userInfo.email_verified = user.email_verified;
      }

      if (scopes.includes('profile')) {
        userInfo.name = user.name;
        userInfo.given_name = user.given_name;
        userInfo.family_name = user.family_name;
        userInfo.picture = user.picture;
        userInfo.preferred_username = user.preferred_username;
        
        // Add additional profile fields
        if (user.locale) userInfo.locale = user.locale;
        if (user.zoneinfo) userInfo.zoneinfo = user.zoneinfo;
        if (user.updated_at) userInfo.updated_at = user.updated_at;
        if (user.birthdate) userInfo.birthdate = user.birthdate;
        if (user.gender) userInfo.gender = user.gender;
        if (user.website) userInfo.website = user.website;
      }

      // Add phone claims if available
      if (scopes.includes('phone') || scopes.includes('profile')) {
        if (user.phone_number) userInfo.phone_number = user.phone_number;
        if (user.phone_number_verified !== undefined) userInfo.phone_number_verified = user.phone_number_verified;
      }

      // Add address claims if available
      if (scopes.includes('address') || scopes.includes('profile')) {
        if (user.address) userInfo.address = user.address;
      }

      // Add custom claims (always include for easier Cognito mapping)
      if (user.custom_department) userInfo.custom_department = user.custom_department;
      if (user.custom_employee_id) userInfo.custom_employee_id = user.custom_employee_id;
      if (user.custom_role) userInfo.custom_role = user.custom_role;

      return userInfo;
    } catch (error) {
      throw new Error('Invalid access token');
    }
  }
} 