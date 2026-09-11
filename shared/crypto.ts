/**
 * shared/crypto.ts — transparent crypto core.
 *
 * - Auto-generates an Ed25519 keypair into keys/ on first run.
 * - Hand-rolls JWT (EdDSA) sign/verify with node:crypto primitives only.
 *
 * No JWT library on purpose (invariant #5: transparency over framework magic).
 * You should be able to explain every line of this file before Phase 2.
 */
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  randomUUID,
  type KeyObject,
} from 'node:crypto';
// existsSync / mkdirSync / readFileSync / writeFileSync live in node:fs, NOT node:crypto.
// A wrong-module named import does NOT fail at import time — it resolves to undefined and
// only explodes as "X is not a function" at the first call. tsx does not type-check!
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  ISSUER,
  AUDIENCE,
  type InternalJwtClaims,
  type JwtVerificationResult,
} from './types';

const KEYS_DIR = path.resolve(__dirname, '..', 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'gateway.private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'gateway.public.pem');

/**
 * Load the keypair, generating it on first run.
 * The PRIVATE key never leaves this machine and is only ever loaded by the gateway.
 * The PUBLIC key is the only thing internal services need — that asymmetry IS the pattern.
 */
export function ensureKeypair(): { privateKey: KeyObject; publicKey: KeyObject } {
  if (!existsSync(PRIVATE_KEY_PATH) || !existsSync(PUBLIC_KEY_PATH)) {
    mkdirSync(KEYS_DIR, { recursive: true });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    writeFileSync(PRIVATE_KEY_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(PUBLIC_KEY_PATH, publicKey.export({ type: 'spki', format: 'pem' }));
    console.log(`[crypto] generated new Ed25519 keypair in ${KEYS_DIR}`);
    return { privateKey, publicKey };
  }
  return {
    privateKey: createPrivateKey(readFileSync(PRIVATE_KEY_PATH, 'utf8')),
    publicKey: createPublicKey(readFileSync(PUBLIC_KEY_PATH, 'utf8')),
  };
}

/** Internal services call this — gateway public key only. Fails fast if the gateway never ran. */
export function loadGatewayPublicKey(): KeyObject {
  if (!existsSync(PUBLIC_KEY_PATH)) {
    throw new Error(
      `${PUBLIC_KEY_PATH} not found — start the gateway once first (it generates the keypair).`,
    );
  }
  return createPublicKey(readFileSync(PUBLIC_KEY_PATH, 'utf8'));
}

const b64url = (input: Buffer | string): string => Buffer.from(input).toString('base64url');

/**
 * Sign claims into a compact JWS:  base64url(header) . base64url(payload) . base64url(signature)
 * The signature covers EXACTLY the first two segments — change one byte and it breaks.
 */
export function signInternalJwt(claims: InternalJwtClaims, privateKey: KeyObject): string {
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  // Ed25519 signs raw bytes directly (no pre-hash step) → the algorithm argument is null.
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

/**
 * Verify exactly the way an internal service must, in the safe order:
 *   1. shape (3 segments)
 *   2. algorithm allowlist — NEVER trust the token's own alg claim
 *   3. signature (crypto.verify is constant-time internally — no timing leaks)
 *   4. expiry, then issuer, then audience — checks are meaningless over an unverified signature
 */
export function verifyInternalJwt(jwt: string, publicKey: KeyObject): JwtVerificationResult {
  const parts = jwt.split('.');
  if (parts.length !== 3) return { valid: false, reason: 'malformed' };
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  let header: { alg?: string };
  try {
    header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'malformed' };
  }
  // Hard allowlist: we only ever mint EdDSA. Kills "alg": "none" and RS/HS confusion attacks.
  if (header.alg !== 'EdDSA') return { valid: false, reason: 'unsupported_alg' };

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signatureOk = verify(
    null,
    Buffer.from(signingInput),
    publicKey,
    Buffer.from(encodedSignature, 'base64url'),
  );
  if (!signatureOk) return { valid: false, reason: 'bad_signature' };

  let claims: InternalJwtClaims;
  try {
    claims = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'malformed' };
  }
  if (typeof claims.exp !== 'number' || claims.exp <= Math.floor(Date.now() / 1000)) {
    return { valid: false, reason: 'expired', claims };
  }
  if (claims.iss !== ISSUER) return { valid: false, reason: 'wrong_issuer', claims };
  if (claims.aud !== AUDIENCE) return { valid: false, reason: 'wrong_audience', claims };
  return { valid: true, claims };
}

/**
 * DEBUG ONLY: decode without verifying. Used by /debug endpoints so you can SEE what a JWT
 * carries. Never gate a decision on this — an unverified decode is reading attacker input.
 */
export function decodeJwtUnchecked(jwt: string): { header: unknown; payload: unknown } {
  const [encodedHeader, encodedPayload] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8')),
    payload: JSON.parse(Buffer.from(encodedPayload ?? '', 'base64url').toString('utf8')),
  };
}

/** Fresh unique token id for the jti claim. */
export const newJti = (): string => randomUUID();