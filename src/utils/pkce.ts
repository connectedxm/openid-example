import crypto from 'crypto';

export function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
  method: string = 'S256'
): boolean {
  console.log(`[PKCE] Verifying code challenge with method: ${method}`);
  console.log(`[PKCE] Code verifier length: ${codeVerifier.length}`);
  console.log(`[PKCE] Code challenge length: ${codeChallenge.length}`);
  
  if (method === 'plain') {
    console.log(`[PKCE] Using plain method`);
    const result = codeVerifier === codeChallenge;
    console.log(`[PKCE] Plain verification result: ${result}`);
    return result;
  } else if (method === 'S256') {
    console.log(`[PKCE] Using S256 method`);
    const hash = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    console.log(`[PKCE] Generated hash: ${hash}`);
    console.log(`[PKCE] Expected challenge: ${codeChallenge}`);
    const result = hash === codeChallenge;
    console.log(`[PKCE] S256 verification result: ${result}`);
    return result;
  }
  
  console.log(`[PKCE] ❌ Unsupported method: ${method}`);
  return false;
}

export function generateAuthorizationCode(): string {
  return crypto.randomBytes(32).toString('hex');
} 