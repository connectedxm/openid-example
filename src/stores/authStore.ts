import { AuthorizationCode, Session } from '../types';
import crypto from 'crypto';

class AuthStore {
  private authCodes: Map<string, AuthorizationCode> = new Map();
  private sessions: Map<string, Session> = new Map();

  // Authorization code methods
  saveAuthCode(code: AuthorizationCode): void {
    console.log(`[AUTH_STORE] Saving authorization code for client: ${code.clientId}, user: ${code.userId}`);
    this.authCodes.set(code.code, code);
    console.log(`[AUTH_STORE] ✅ Authorization code saved, expires at: ${code.expiresAt.toISOString()}`);
    
    // Auto-cleanup after expiration
    setTimeout(() => {
      console.log(`[AUTH_STORE] Auto-cleaning expired authorization code`);
      this.authCodes.delete(code.code);
    }, 10 * 60 * 1000); // 10 minutes
  }

  getAuthCode(code: string): AuthorizationCode | undefined {
    console.log(`[AUTH_STORE] Looking up authorization code`);
    const authCode = this.authCodes.get(code);
    if (authCode && authCode.expiresAt > new Date()) {
      console.log(`[AUTH_STORE] ✅ Valid authorization code found`);
      return authCode;
    }
    console.log(`[AUTH_STORE] ❌ Authorization code not found or expired`);
    this.authCodes.delete(code);
    return undefined;
  }

  consumeAuthCode(code: string): AuthorizationCode | undefined {
    console.log(`[AUTH_STORE] Consuming authorization code`);
    const authCode = this.getAuthCode(code);
    if (authCode) {
      console.log(`[AUTH_STORE] ✅ Authorization code consumed and deleted`);
      this.authCodes.delete(code);
      return authCode;
    }
    console.log(`[AUTH_STORE] ❌ Authorization code not available for consumption`);
    return undefined;
  }

  // Session methods
  createSession(userId: string): string {
    console.log(`[AUTH_STORE] Creating session for user: ${userId}`);
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session: Session = {
      sessionId,
      userId,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    };
    this.sessions.set(sessionId, session);
    console.log(`[AUTH_STORE] ✅ Session created: ${sessionId}, expires at: ${session.expiresAt.toISOString()}`);
    return sessionId;
  }

  getSession(sessionId: string): Session | undefined {
    console.log(`[AUTH_STORE] Looking up session: ${sessionId}`);
    const session = this.sessions.get(sessionId);
    if (session && session.expiresAt > new Date()) {
      console.log(`[AUTH_STORE] ✅ Valid session found for user: ${session.userId}`);
      return session;
    }
    console.log(`[AUTH_STORE] ❌ Session not found or expired`);
    this.sessions.delete(sessionId);
    return undefined;
  }

  deleteSession(sessionId: string): void {
    console.log(`[AUTH_STORE] Deleting session: ${sessionId}`);
    const deleted = this.sessions.delete(sessionId);
    console.log(`[AUTH_STORE] ${deleted ? '✅ Session deleted' : '❌ Session not found'}`);
  }
}

export default new AuthStore(); 