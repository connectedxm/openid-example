import { AuthorizationCode, Session } from '../types';
import crypto from 'crypto';

class AuthStore {
  private authCodes: Map<string, AuthorizationCode> = new Map();
  private sessions: Map<string, Session> = new Map();

  // Authorization code methods
  saveAuthCode(code: AuthorizationCode): void {
    this.authCodes.set(code.code, code);
    
    // Auto-cleanup after expiration
    setTimeout(() => {
      this.authCodes.delete(code.code);
    }, 10 * 60 * 1000); // 10 minutes
  }

  getAuthCode(code: string): AuthorizationCode | undefined {
    const authCode = this.authCodes.get(code);
    if (authCode && authCode.expiresAt > new Date()) {
      return authCode;
    }
    this.authCodes.delete(code);
    return undefined;
  }

  consumeAuthCode(code: string): AuthorizationCode | undefined {
    const authCode = this.getAuthCode(code);
    if (authCode) {
      this.authCodes.delete(code);
      return authCode;
    }
    return undefined;
  }

  // Session methods
  createSession(userId: string): string {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session: Session = {
      sessionId,
      userId,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    };
    this.sessions.set(sessionId, session);
    return sessionId;
  }

  getSession(sessionId: string): Session | undefined {
    const session = this.sessions.get(sessionId);
    if (session && session.expiresAt > new Date()) {
      return session;
    }
    this.sessions.delete(sessionId);
    return undefined;
  }

  deleteSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

export default new AuthStore(); 