/**
 * apps/gateway/translator.ts — the heart of the Phantom Token Pattern.
 *
 * Takes a verified opaque-token record and mints a short-lived internal JWT
 * signed with the gateway PRIVATE key. Downstream services verify it with the
 * public key. The two token species never meet anywhere else but here.
 */

import { ensureKeypair, signInternalJwt, newJti } from '../../shared/crypto';

import {
  ISSUER,
  AUDIENCE,
  INTERNAL_JWT_TTL_SECONDS,
  type InternalJwtClaims,
  type OpaqueTokenRecord,
} from '../../shared/types';

const { privateKey } = ensureKeypair();

export function exchangeOpaqueToJwt(record: OpaqueTokenRecord): {
  jwt: string;
  claims: InternalJwtClaims;
} {
  const now = Math.floor(Date.now() / 1000);
  const claims: InternalJwtClaims = {
    iss: ISSUER,
    sub: record.session.userId,
    aud: AUDIENCE,
    roles: record.session.roles,
    tenant: record.session.tenantId,
    tier: record.session.tier,
    allowed_models: record.session.allowedModels,
    quota_remaining: record.session.quotaRemaining,
    iat: now,
    exp: now + INTERNAL_JWT_TTL_SECONDS, // short-lived: a leaked internal JWT dies alone
    jti: newJti(),
  };

  const jwt = signInternalJwt(claims, privateKey);

  return {
    jwt,
    claims,
  };
}
