/**
 * experiments/04-benchmark.ts — E4: why the internal mesh scales.
 *
 * Compares per-request auth cost:
 *   (a) local Ed25519 JWT verification  — what EVERY internal service pays
 *   (b) simulated introspection round-trip (Map lookup + network latency)
 *       — what "pure opaque everywhere" (plan.md §1.2 Option B) would pay
 *
 * HONEST CAVEAT: (b) uses a synthetic sleep for the network hop. Real numbers
 * vary: Ed25519 verify ≈ 0.02–0.05 ms; real Redis/auth-server hop ≈ 0.3–2 ms.
 * Tune with: CRYPTO_ITERS, STORE_ITERS, STORE_LATENCY_MS.
 */
import { generateKeyPairSync } from 'node:crypto';
import { signInternalJwt, verifyInternalJwt } from '../shared/crypto';
import { ISSUER, AUDIENCE, type InternalJwtClaims } from '../shared/types';

const CRYPTO_ITERS = Number(process.env.CRYPTO_ITERS ?? 10_000);
const STORE_ITERS = Number(process.env.STORE_ITERS ?? 1_000);
const STORE_LATENCY_MS = Number(process.env.STORE_LATENCY_MS ?? 2);

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// Ephemeral keypair — the benchmark does not need (and does not touch) keys/.
const { privateKey, publicKey } = generateKeyPairSync('ed25519');

const now = Math.floor(Date.now() / 1000);
const claims: InternalJwtClaims = {
  iss: ISSUER,
  sub: 'dev_bench',
  aud: AUDIENCE,
  roles: ['developer'],
  tenant: 'org_bench',
  tier: 'enterprise',
  allowed_models: ['gpt-4o'],
  quota_remaining: 1000,
  iat: now,
  exp: now + 600,
  jti: 'bench',
};
const jwt = signInternalJwt(claims, privateKey);

// ── (a) local CPU verification ───────────────────────────────────────────────
for (let i = 0; i < 200; i++) verifyInternalJwt(jwt, publicKey); // warm-up

const t0 = performance.now();
let verified = 0;
for (let i = 0; i < CRYPTO_ITERS; i++) {
  if (verifyInternalJwt(jwt, publicKey).valid) verified++;
}
const cryptoMs = performance.now() - t0;
if (verified !== CRYPTO_ITERS) throw new Error('verification unexpectedly failed');

// ── (b) simulated introspection: lookup + network hop ───────────────────────
const store = new Map<string, { session: { userId: string } }>([
  ['sk_live_bench', { session: { userId: 'dev_bench' } }],
]);

async function main(): Promise<void> {
  const t1 = performance.now();
  for (let i = 0; i < STORE_ITERS; i++) {
    const record = store.get('sk_live_bench');
    if (!record) throw new Error('store miss');
    await sleep(STORE_LATENCY_MS); // the hop to Redis / auth server
  }
  const storeMs = performance.now() - t1;

// ── report ───────────────────────────────────────────────────────────────────
const cryptoPerOp = cryptoMs / CRYPTO_ITERS;
const storePerOp = storeMs / STORE_ITERS;
const ratio = storePerOp / cryptoPerOp;

const line = '─'.repeat(64);
console.log(`\n${line}`);
console.log(' E4 — per-request auth cost: local verify vs store round-trip');
console.log(line);
console.log(
  ` local Ed25519 verify (CPU)   ${String(CRYPTO_ITERS).padStart(7)} iters` +
    ` ${cryptoMs.toFixed(1).padStart(9)} ms   ${cryptoPerOp.toFixed(4).padStart(9)} ms/op`,
);
console.log(
  ` introspection (+${STORE_LATENCY_MS}ms hop)    ${String(STORE_ITERS).padStart(7)} iters` +
    ` ${storeMs.toFixed(1).padStart(9)} ms   ${storePerOp.toFixed(4).padStart(9)} ms/op`,
);
console.log(line);
console.log(` ratio: a store round-trip costs ≈ ${ratio.toFixed(0)}× a local verification`);
console.log(` ⇒ 1 user action × 3 internal hops: internal mesh pays ~${(cryptoPerOp * 3).toFixed(3)} ms,`);
console.log(`   Option B (opaque everywhere) pays ~${(storePerOp * 3).toFixed(2)} ms of pure auth latency.`);
console.log(`${line}`);
console.log(' caveat: synthetic latency — real Ed25519 ≈ 0.02–0.05 ms/op,');
console.log(' real Redis hop ≈ 0.3–2 ms/op. The ORDER of magnitude is the lesson.\n');
}

void main();
