/**
 * apps/gateway/token-store.ts — the STATEFUL side of the lab.
 *
 * The external credential (sk_live_...) carries zero identity data: it is just a
 * lookup key. Whoever holds this store's state holds the truth — which is exactly
 * why deleting one entry here revokes a token INSTANTLY, everywhere.
 *
 * In production this would be Redis / a clustered cache (see plan.md §7.2).
 * INTROSPECTION_DELAY_MS simulates the network hop a real store adds to EVERY
 * request — set it (e.g. INTROSPECTION_DELAY_MS=2) to feel the cost of stateful
 * validation, then compare with the 0.0x ms JWT verify from Phase 1.
 */

import { randomBytes } from 'node:crypto';

import {
  OPAQUE_TOKEN_TTL_SECONDS,
  type OpaqueTokenRecord,
  type UserSession,
} from '../../shared/types';

const INTROSPECTION_DELAY_MS = Number(process.env.INTROSPECTION_DELAY_MS ?? 0);
const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const MOCK_USERS: Array<UserSession & { password: string }> = [
  {
    username: 'athalla',
    password: 'secret',
    userId: 'dev_99',
    roles: ['developer'],
    tenantId: 'org_acme',
    tier: 'enterprise',
    allowedModels: ['gpt-4o', 'claude-sonnet-5', 'llama-3.1-405b'],
    quotaRemaining: 5000,
  },
  {
    username: 'demo',
    password: 'secret',
    userId: 'dev_07',
    roles: ['developer'],
    tenantId: 'org_demo',
    tier: 'free',
    allowedModels: ['llama-3.1-8b'],
    quotaRemaining: 25,
  },
];

export class TokenStore {
  /** token -> session record. This Map IS the "state" in "stateful". */
  private readonly sessions = new Map<string, OpaqueTokenRecord>();

  authenticate(username: string, password: string): UserSession | null {
    const user = MOCK_USERS.find(
      (candidate) =>
        candidate.username === username && candidate.password === password,
    );

    if (!user) return null;

    const { password: _stripped, ...session } = user;
    return session;
  }

  /**
   * Issue a fresh opaque token. randomBytes only — no encoded metadata, nothing to
   * leak if the token is stolen. Compare with the JWT: meaningful to anyone who reads it.
   */
  createSession(session: UserSession): string {
    const token = `sk_live_${randomBytes(24).toString('base64url')}`;
    const now = Date.now();

    this.sessions.set(token, {
      token,
      session,
      createdAt: now,
      expiresAt: now + OPAQUE_TOKEN_TTL_SECONDS * 1000,
    });

    return token;
  }

  /**
   * What the gateway does ONCE per request, at the perimeter.
   * Returns null for unknown/expired tokens — the caller MUST 401 before any
   * downstream service is ever contacted.
   */
  async introspectToken(token: string): Promise<OpaqueTokenRecord | null> {
    if (INTROSPECTION_DELAY_MS > 0) {
      await sleep(INTROSPECTION_DELAY_MS);
    }

    const record = this.sessions.get(token);
    if (!record) return null;
    if (record.expiresAt <= Date.now()) {
      this.sessions.delete(token);
      return null;
    }

    return record;
  }

  /** Instant revocation: delete the record, and the token becomes meaningless bytes. */
  revokeToken(token: string): boolean {
    return this.sessions.delete(token);
  }
}
