/**
 * apps/quota-service/verifier.ts — standalone zero-trust gate for quota-service.
 *
 * A deliberate near-copy of prompt-service/verifier.ts. In this lab, every
 * service owns its verification. Even if prompt-service were fully compromised,
 * quota-service would still demand a valid gateway signature — trust is never
 * transferred between services, only proven cryptographically.
 */
import type { IncomingMessage } from 'node:http';
import { loadGatewayPublicKey, verifyInternalJwt } from '../../shared/crypto';
import type { JwtVerificationResult } from '../../shared/types';

const gatewayPublicKey = loadGatewayPublicKey();

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

export function verifyRequestToken(
  req: IncomingMessage,
): JwtVerificationResult {
  const jwt = extractBearer(req);
  if (!jwt) return { valid: false, reason: 'malformed' };
  return verifyInternalJwt(jwt, gatewayPublicKey);
}
