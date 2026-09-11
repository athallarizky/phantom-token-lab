/**
 * shared/types.ts — the shared vocabulary of the Phantom Token Lab.
 *
 * Two token species live side by side on purpose:
 *  - OpaqueTokenRecord: the EXTERNAL credential (stateful, meaningless bytes, revocable)
 *  - InternalJwtClaims: the INTERNAL identity (stateless, signed, self-describing, short-lived)
 */

/** Who mints internal JWTs. Services reject tokens signed by anyone else. */
export const ISSUER = 'phantom-gateway';

/** Who internal JWTs are for. Services reject tokens meant for someone else. */
export const AUDIENCE = 'internal-services';

/** Lifetime of the internal JWT, in seconds. Short on purpose: a leaked JWT dies alone. */
export const INTERNAL_JWT_TTL_SECONDS = 120;

/** Lifetime of the external opaque token (API key), in seconds. */
export const OPAQUE_TOKEN_TTL_SECONDS = 60 * 60;

export type Tier = 'free' | 'pro' | 'enterprise';

/** Everything the lab knows about a logged-in developer. Lives ONLY inside the gateway. */
export interface UserSession {
  userId: string; // e.g. "dev_99" — becomes the JWT "sub" claim
  username: string;
  roles: string[];
  tenantId: string; // e.g. "org_acme"
  tier: Tier;
  allowedModels: string[]; // Track A: which AI models this developer may call
  quotaRemaining: number; // credit balance snapshot at login
}

/**
 * The stateful side of the pattern. The token itself is RANDOM BYTES carrying
 * zero identity — the record (not the token) holds the meaning.
 */
export interface OpaqueTokenRecord {
  token: string; // "sk_live_..." — opaque lookup key, nothing more
  session: UserSession;
  createdAt: number; // epoch ms
  expiresAt: number; // epoch ms
}

/**
 * The stateless side. Every field here travels INSIDE the signed JWT payload.
 * snake_case fields (allowed_models, quota_remaining) match JWT claim conventions.
 */
export interface InternalJwtClaims {
  iss: string; // issuer: "phantom-gateway"
  sub: string; // subject: user id, e.g. "dev_99"
  aud: string; // audience: "internal-services"
  roles: string[];
  tenant: string;
  tier: Tier;
  allowed_models: string[];
  quota_remaining: number;
  iat: number; // issued-at (epoch seconds)
  exp: number; // expiry (epoch seconds) = iat + INTERNAL_JWT_TTL_SECONDS
  jti: string; // unique token id — a handle for audit logs / future denylists
}

/** Why a verification failed — precise reasons make debugging (and Phase 4 experiments) observable. */
export type VerificationFailureReason =
  | 'malformed'
  | 'unsupported_alg'
  | 'bad_signature'
  | 'expired'
  | 'wrong_issuer'
  | 'wrong_audience';

export interface JwtVerificationResult {
  valid: boolean;
  claims?: InternalJwtClaims;
  reason?: VerificationFailureReason;
}