/**
 * apps/quota-service/server.ts — internal service :3002 (the crown jewels).
 *
 * Deducts usage credits. Accepts ONLY signed gateway JWTs; forged X-User-*
 * headers never influence identity. Note the two kinds of state in play:
 *  - auth state: NONE — identity arrives verified and stateless, inside the JWT
 *  - business state: balances Map — quota-service's own domain data,
 *    like a real accounts table. Auth is stateless; business is not.
 */
import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { verifyRequestToken, warnForgedHeaders } from './verifier';
import type { InternalJwtClaims } from '../../shared/types';

const PORT = 3002;

const TAG = '\x1b[33m[quota-service]\x1b[0m';
const dim = (text: string) => `\x1b[2m${text}\x1b[0m`;
const log = (message: string) =>
  console.log(
    `${TAG} ${dim(new Date().toISOString().slice(11, 23))} ${message}`,
  );

const stats = { requests: 0, verified: 0, rejected: 0, spoof_attempts: 0 };

/** sub → remaining credits. BUSINESS state (not auth state). In-memory = lab scope. */
const balances = new Map<string, number>();

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(
          chunks.length === 0
            ? {}
            : JSON.parse(Buffer.concat(chunks).toString('utf8')),
        );
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  try {
    // route: /healtz
    if (req.method === 'GET' && url.pathname === '/healthz') {
      return send(res, 200, {
        service: 'quota-service',
        status: 'ok',
        uptime_s: Math.round(process.uptime()),
      });
    }

    // route: /stats
    if (req.method === 'GET' && url.pathname === '/stats') {
      return send(res, 200, {
        service: 'quota-service',
        ...stats,
        tracked_accounts: balances.size,
      });
    }

    // route: /quota/deduct
    if (req.method === 'POST' && url.pathname === '/quota/deduct') {
      stats.requests++;
      stats.spoof_attempts += warnForgedHeaders(req, log);

      const result = verifyRequestToken(req);
      if (!result.valid || !result.claims) {
        stats.rejected++;
        log(
          `⛔ JWT rejected (${result.reason ?? 'unknown'}) — identity MUST come from a gateway signature`,
        );
        return send(res, 401, {
          error: 'invalid_token',
          reason: result.reason ?? 'unknown',
        });
      }
      stats.verified++;

      const claims: InternalJwtClaims = result.claims;
      // Identity: ONLY from the verified signature. Everything else is noise.
      log(
        `✅ JWT verified locally: sub=${claims.sub} — deducting on THIS identity`,
      );

      const body = await readJson(req);
      const amount = Math.max(1, Math.floor(Number(body.amount ?? 1)));

      // Bootstrap: first time we see this sub, seed the balance from the claim.
      // After this moment the live balance belongs to quota-service, not to the JWT.
      if (!balances.has(claims.sub)) {
        balances.set(claims.sub, claims.quota_remaining);
        log(
          `first sight of ${claims.sub} — seeded ${claims.quota_remaining} credits from JWT claim (live balance is ours now)`,
        );
      }

      const remaining = balances.get(claims.sub)!;
      if (remaining < amount) {
        log(
          `⛔ quota exceeded for ${claims.sub} (remaining ${remaining}, wanted ${amount})`,
        );
        return send(res, 402, {
          error: 'quota_exceeded',
          sub: claims.sub,
          remaining,
        });
      }

      balances.set(claims.sub, remaining - amount);
      log(
        `deducted ${amount} for sub=${claims.sub} → remaining ${remaining - amount}`,
      );
      return send(res, 200, {
        sub: claims.sub,
        deducted: amount,
        remaining: remaining - amount,
      });
    }

    return send(res, 404, {
      error: 'not_found',
      route: `${req.method} ${url.pathname}`,
    });
  } catch (error) {
    log(`ERROR: ${(error as Error).message}`);
    return send(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, () => {
  log(`quota-service listening on :${PORT} (internal zone, crown jewels)`);
});
