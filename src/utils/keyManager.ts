import { generateKeyPairSync } from 'crypto';
import jwt from 'jsonwebtoken';
import * as jose from 'node-jose';

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

  async getJWKS(): Promise<any> {
    try {
      // Use node-jose to properly convert PEM to JWK
      const keystore = jose.JWK.createKeyStore();
      const key = await keystore.add(this.keyPair.publicKey, 'pem');
      
      // Convert to JWK format
      const jwk = key.toJSON();
      
      return {
        keys: [
          {
            ...jwk,
            kid: this.keyPair.kid,
            use: 'sig',
            alg: 'RS256'
          }
        ]
      };
    } catch (error) {
      console.error('Error generating JWKS:', error);
      // Fallback to basic JWK structure if node-jose fails
      return {
        keys: [
          {
            kty: 'RSA',
            kid: this.keyPair.kid,
            use: 'sig',
            alg: 'RS256',
            n: 'fallback-key',
            e: 'AQAB'
          }
        ]
      };
    }
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