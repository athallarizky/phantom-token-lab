/**
 * apps/prompt-service/server.ts — internal service :3001.
 *
 * Zero-trust rules this process lives by:
 *  - never sees sk_live_... tokens (those die at the gateway perimeter)
 *  - never queries an auth DB — identity = locally verified JWT claims
 *  - propagates the SAME JWT to quota-service (service-to-service chain)
 *  - makes its own authorization decision (allowed_models) from claims
 */
import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
  extractBearer,
  verifyRequestToken,
  warnForgedHeaders,
} from './verifier';
import type { InternalJwtClaims } from '../../shared/types';

const PORT = 3001;
const QUOTA_SERVICE_URL =
  process.env.QUOTA_SERVICE_URL ?? 'http://127.0.0.1:3002';

const TAG = '\x1b[35m[prompt-service]\x1b[0m';
const dim = (text: string) => `\x1b[2m${text}\x1b[0m'`;
const log = (message: string) =>
  console.log(
    `${TAG} ${dim(new Date().toISOString().slice(11, 23))} ${message}`,
  );

// Observability counters — experiments E2/E3 read these via GET /stats.
const stats = { requests: 0, verified: 0, rejected: 0, spoof_attempts: 0 };

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

/**
 * Call quota-service with the SAME JWT that arrived here.
 * Trust is never transferred — quota-service re-verifies the signature itself.
 */
async function deductQuota(
  jwt: string,
  amount: number,
  model: string,
): Promise<{ status: number; body: unknown }> {
  try {
    const response = await fetch(`${QUOTA_SERVICE_URL}/quota/deduct`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${jwt}`, // ← same token, propagated
      },
      body: JSON.stringify({ amount, model }),
      signal: AbortSignal.timeout(5000),
    });

    const text = await response.text();
    try {
      return { status: response.status, body: JSON.parse(text) };
    } catch {
      return { status: response.status, body: text };
    }
  } catch (error) {
    log(`⚠️  quota-service unreachable: ${(error as Error).message}`);
    return {
      status: 502,
      body: { error: 'bad_gateway', detail: 'quota-service unreachable' },
    };
  }
}

/** The zero-trust entry check. Returns claims or sends a 401 itself. */
function requireVerifiedJwt(
  req: IncomingMessage,
  res: ServerResponse,
  claimsOut: { jwt: string | null; claims: InternalJwtClaims | null },
): boolean {
  stats.requests++;
  stats.spoof_attempts += warnForgedHeaders(req, log);

  const jwt = extractBearer(req);
  const result = verifyRequestToken(req);
  if (!result.valid || !result.claims) {
    stats.rejected++;
    log(
      `⛔ JWT rejected (${result.reason ?? 'unknown'}) — no DB was consulted, signature decided`,
    );
    send(res, 401, {
      error: 'invalid_token',
      reason: result.reason ?? 'unknown',
    });
    return false;
  }
  stats.verified++;
  log(
    `✅ JWT verified locally: sub=${result.claims.sub} tenant=${result.claims.tenant} tier=${result.claims.tier}`,
  );
  claimsOut.jwt = jwt;
  claimsOut.claims = result.claims;
  return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  try {
    // route: /healtz
    if (req.method === 'GET' && url.pathname === '/healthz') {
      return send(res, 200, {
        service: 'prompt-service',
        status: 'ok',
        uptime_s: Math.round(process.uptime()),
      });
    }

    // route: /stats
    if (req.method === 'GET' && url.pathname === '/stats') {
      return send(res, 200, { service: 'prompt-service', ...stats });
    }

    // route: /models
    // What am I allowed to call? Read straight from verified claims — no DB.
    if (req.method === 'GET' && url.pathname === '/models') {
      const ctx: { jwt: string | null; claims: InternalJwtClaims | null } = {
        jwt: null,
        claims: null,
      };
      if (!requireVerifiedJwt(req, res, ctx)) return;
      return send(res, 200, {
        sub: ctx.claims!.sub,
        allowed_models: ctx.claims!.allowed_models,
        source: 'verified JWT claims — zero database lookups',
      });
    }

    // route: /completions
    if (req.method === 'POST' && url.pathname === '/completions') {
      const ctx: { jwt: string | null; claims: InternalJwtClaims | null } = {
        jwt: null,
        claims: null,
      };
      if (!requireVerifiedJwt(req, res, ctx)) return;
      const claims = ctx.claims!;

      const body = await readJson(req);
      const model = String(body.model ?? '');
      const prompt = String(body.prompt ?? '');

      // AUTHORIZATION: decided here, from verified claims alone.
      if (!claims.allowed_models.includes(model)) {
        log(
          `⛔ model "${model}" not in allowed_models claim → 403 (authorization from claims, not from a DB)`,
        );
        return send(res, 403, {
          error: 'model_not_allowed',
          model,
          allowed_models: claims.allowed_models,
        });
      }

      // Mock completion — deterministic, no real model call. This is a lab.
      const text =
        `[MOCK:${model}] ${prompt.trim().slice(0, 80)} — ` +
        `"The phantom token pattern separates the external credential from the internal identity."`;

      // Service-to-service: propagate the SAME JWT. quota-service re-verifies.
      const quota = await deductQuota(ctx.jwt!, 1, model);
      if (quota.status !== 200) {
        log(`← quota-service refused (${quota.status}) — relaying to caller`);
        return send(res, quota.status, quota.body);
      }
      log(
        `→ quota-service deducted 1 credit for sub=${claims.sub} (same JWT, verified independently)`,
      );

      return send(res, 200, {
        id: `cmpl_${randomBytes(6).toString('hex')}`,
        object: 'text_completion',
        model,
        sub: claims.sub,
        choices: [{ text }],
        usage: {
          prompt_tokens: prompt.split(/\s+/).length,
          completion_tokens: 24,
          cost: 1,
        },
        quota: quota.body,
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
  log(`prompt-service listening on :${PORT} (internal zone)`);
  log(
    `outbound calls to ${QUOTA_SERVICE_URL} will carry the caller's JWT unchanged`,
  );
});
