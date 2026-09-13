/**
 * apps/prompt-service/verifier.ts — the zero-trust gate for prompt-service.
 *
 * Identity enters this service ONLY through a cryptographically verified JWT
 * (gateway public key). Plain identity headers (X-User-Id, X-Role, ...) carry
 * ZERO trust: they are logged and ignored.
 *
 * Deliberately standalone — a near-identical copy lives in quota-service.
 * Each service verifies independently; no service ever trusts
 * "the caller already checked it".
 */

import type { IncomingMessage } from 'node:http';
import { loadGatewayPublicKey, verifyInternalJwt } from '../../shared/crypto';
import type { JwtVerificationResult } from '../../shared/types';

// Loaded ONCE at boot. PUBLIC key only — this process could not mint a valid
// token even if it wanted to. That asymmetry is the architecture.
const gatewayPublicKey = loadGatewayPublicKey();

/** Headers attackers use to smuggle identity into naive services. */
const FORGED_IDENTITY_HEADERS = [
  'x-user-id',
  'x-user-role',
  'x-role',
  'x-tenant-id',
  'x-quota-remaining',
];

export function extractBearer(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  return typeof header === 'string' && header.startsWith('Bearer ')
    ? header.slice(7)
    : null;
}

/**
 * Detect and loudly ignore identity-by-header attempts. Returns the count so
 * /stats can track spoof attempts (experiment E3 reads this number).
 */
export function warnForgedHeaders(
  req: IncomingMessage,
  log: (message: string) => void,
): number {
  const present = FORGED_IDENTITY_HEADERS.filter(
    (name) => req.headers[name] !== undefined,
  );
  if (present.length > 0) {
    log(
      `⚠️  forged identity header(s) [${present.join(', ')}] — IGNORED. Identity comes only from the signed JWT.`,
    );
  }
  return present.length;
}

/** Extract + verify. The ONLY path identity can take into this service. */
export function verifyRequestToken(
  req: IncomingMessage,
): JwtVerificationResult {
  const jwt = extractBearer(req);
  if (!jwt) return { valid: false, reason: 'malformed' };
  return verifyInternalJwt(jwt, gatewayPublicKey);
}
