import { generateKeyPairSync } from 'crypto';
import jwt from 'jsonwebtoken';

interface KeyPair {
  privateKey: string;
  publicKey: string;
  kid: string;
}

class KeyManager {
  private keyPair: KeyPair;

  constructor() {
    this.keyPair = this.generateKeyPair();
  }

  private generateKeyPair(): KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    return {
      privateKey,
      publicKey,
      kid: 'key-1' // Simple key ID for testing
    };
  }

  getPrivateKey(): string {
    return this.keyPair.privateKey;
  }

  getPublicKey(): string {
    return this.keyPair.publicKey;
  }

  getKid(): string {
    return this.keyPair.kid;
  }

  getJWKS(): any {
    // Convert PEM to JWK format for JWKS endpoint
    const key = this.pemToJWK(this.keyPair.publicKey);
    return {
      keys: [
        {
          ...key,
          kid: this.keyPair.kid,
          use: 'sig',
          alg: 'RS256'
        }
      ]
    };
  }

  private pemToJWK(pem: string): any {
    // Simple conversion - in production, use a library like node-jose
    const publicKey = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\n/g, '');
    
    return {
      kty: 'RSA',
      n: publicKey, // This is simplified - in production, extract modulus properly
      e: 'AQAB' // Standard RSA exponent (65537)
    };
  }

  signToken(payload: any, expiresIn: string = '1h'): string {
    return jwt.sign(payload, this.keyPair.privateKey, {
      algorithm: 'RS256',
      expiresIn,
      header: {
        kid: this.keyPair.kid,
        typ: 'JWT'
      }
    } as jwt.SignOptions);
  }

  verifyToken(token: string): any {
    return jwt.verify(token, this.keyPair.publicKey, {
      algorithms: ['RS256']
    });
  }
}

export default new KeyManager(); 