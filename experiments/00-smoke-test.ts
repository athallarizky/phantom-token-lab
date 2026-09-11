/**
 * E0 — crypto smoke test (Phase 1 gate).
 * Proves, with zero HTTP in the picture:
 *   1. keypair auto-generation works
 *   2. sign -> verify round-trip works
 *   3. tampering with the payload breaks the signature
 *   4. expired tokens are rejected
 *   5. alg:"none" forgery is rejected
 */
import { ensureKeypair, signInternalJwt, verifyInternalJwt } from '../shared/crypto';
import { ISSUER, AUDIENCE, type InternalJwtClaims } from '../shared/types';

const assert = (condition: boolean, label: string): void => {
  console.log(`${condition ? '  ✅' : '  ❌'} ${label}`);
  if (!condition) process.exitCode = 1;
};

const { privateKey, publicKey } = ensureKeypair();

const now = Math.floor(Date.now() / 1000);
const claims: InternalJwtClaims = {
  iss: ISSUER,
  sub: 'dev_99',
  aud: AUDIENCE,
  roles: ['developer'],
  tenant: 'org_acme',
  tier: 'enterprise',
  allowed_models: ['gpt-4o'],
  quota_remaining: 5000,
  iat: now,
  exp: now + 120,
  jti: 'smoke-test-jti',
};

const jwt = signInternalJwt(claims, privateKey);
console.log('\nsigned JWT:');
console.log(`  ${jwt.slice(0, 50)}...`);
console.log(`  header   = ${Buffer.from(jwt.split('.')[0], 'base64url').toString()}`);
console.log(`  payload  = ${Buffer.from(jwt.split('.')[1], 'base64url').toString()}\n`);

// 1 — honest round-trip
assert(verifyInternalJwt(jwt, publicKey).valid, 'valid token verifies (signature + exp + iss + aud)');

// 2 — attacker rewrites the payload but keeps the old signature
const [h, p, s] = jwt.split('.');
const evilPayload = Buffer.from(
  JSON.stringify({ ...claims, sub: 'dev_01', tier: 'enterprise' }),
).toString('base64url');
assert(
  verifyInternalJwt(`${h}.${evilPayload}.${s}`, publicKey).reason === 'bad_signature',
  'tampered payload rejected: bad_signature',
);

// 3 — honestly signed, but expired
const expiredClaims = { ...claims, iat: now - 300, exp: now - 60 };
assert(
  verifyInternalJwt(signInternalJwt(expiredClaims, privateKey), publicKey).reason === 'expired',
  'expired token rejected: expired',
);

// 4 — alg:none forgery with no signature at all
const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
assert(
  verifyInternalJwt(`${forgedHeader}.${p}.`, publicKey).reason === 'unsupported_alg',
  'alg:"none" forgery rejected: unsupported_alg',
);

console.log(
  process.exitCode
    ? '\n❌ smoke test FAILED — fix above before Phase 2'
    : '\n✅ Phase 1 complete: the gateway can mint, the services can verify.',
);