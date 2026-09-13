import http, {
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { TokenStore } from './token-store';
import { exchangeOpaqueToJwt } from './translator';
import { decodeJwtUnchecked } from '../../shared/crypto';

import {
  INTERNAL_JWT_TTL_SECONDS,
  OPAQUE_TOKEN_TTL_SECONDS,
  type OpaqueTokenRecord,
} from '../../shared/types';

const PORT = 3000;
const PROMPT_SERVICE_URL =
  process.env.PROMPT_SERVICE_URL ?? 'http://127.0.0.1:3001';
const store = new TokenStore();

// ── logging (ANSI colors, no library on purpose)
const TAG = '\x1b[36m[gateway]\x1b[0m';
const dim = (text: string) => `\x1b[2m${text}\x1b[0m`;
const log = (message: string) =>
  console.log(
    `${TAG} ${dim(new Date().toISOString().slice(11, 23))} ${message}`,
  );
/** Never log full credentials — prefix + suffix is enough to correlate log lines. */
const mask = (token: string) => `${token.slice(0, 12)}…${token.slice(-4)}`;

// ── HTTP helpers
function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  return typeof header === 'string' && header.startsWith('Bearer ')
    ? header.slice(7)
    : null;
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
      } catch (error) {
        reject(new Error('invalid JSON body'));
      }
    });
  });
}

/**
 * Forward a request to prompt-service with a REWRITTEN Authorization header.
 * Headers are built from scratch — client-supplied headers are NEVER forwarded
 * wholesale. The opaque token stays at the perimeter; the minted JWT goes in.
 */
async function forwardToPromptService(
  path: string,
  method: 'POST' | 'GET',
  jwt: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  try {
    const response = await fetch(`${PROMPT_SERVICE_URL}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${jwt}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });

    const text = await response.text();

    try {
      return { status: response.status, body: JSON.parse(text) };
    } catch {
      return { status: response.status, body: text };
    }
  } catch (error) {
    log(`⚠️  prompt-service unreachable: ${(error as Error).message}`);
    return {
      status: 502,
      body: { error: 'bad_gateway', detail: 'prompt-service unreachable' },
    };
  }
}

/**
 * THE PERIMETER. Validates the opaque token exactly once per request.
 * Returns the live record, or null (caller must 401 — downstream never called).
 */
async function enforcePerimeter(
  req: IncomingMessage,
): Promise<OpaqueTokenRecord | null> {
  const token = bearerToken(req);

  if (!token) {
    log('⛔ no bearer token — rejected at the perimeter');
    return null;
  }

  const record = await store.introspectToken(token);
  if (!record) {
    log(
      `⛔ token ${mask(token)} unknown/expired/revoked — BLOCKED AT PERIMETER, downstream never called`,
    );
    return null;
  }
  return record;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const route = `${req.method} ${url.pathname}`;

  try {
    // Liveness probe — also used by scripts/start-all.ts in Phase 4.
    if (req.method === 'GET' && url.pathname === '/healthz') {
      return send(res, 200, {
        service: 'gateway',
        status: 'ok',
        uptime_s: Math.round(process.uptime()),
      });
    }

    // ── login: the ONLY place an opaque token is born ────────────────────────
    if (req.method === 'POST' && url.pathname === '/auth/login') {
      const body = await readJson(req);
      const session = store.authenticate(
        String(body.username ?? ''),
        String(body.password ?? ''),
      );
      if (!session) {
        log(`LOGIN FAILED for "${String(body.username ?? '')}"`);
        return send(res, 401, { error: 'invalid_credentials' });
      }
      const token = store.createSession(session);
      log(
        `LOGIN ok — issued opaque token ${mask(token)} for ${session.userId} (tier=${session.tier})`,
      );
      // NOTE: no JWT is ever returned here. Invariant #1 — the client never sees the JWT.
      return send(res, 200, {
        token,
        token_type: 'Bearer',
        expires_in: OPAQUE_TOKEN_TTL_SECONDS,
        developer: {
          userId: session.userId,
          username: session.username,
          tier: session.tier,
          allowed_models: session.allowedModels,
          quota_remaining: session.quotaRemaining,
        },
      });
    }

    // ── logout: instant revocation ───────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/auth/logout') {
      const token = bearerToken(req);
      if (!token || !store.revokeToken(token)) {
        return send(res, 401, { error: 'invalid_token' });
      }
      log(
        `LOGOUT — token ${mask(token)} revoked; introspection will now fail instantly`,
      );
      return send(res, 200, { revoked: true });
    }

    // ── DEBUG: watch the phantom exchange with your own eyes ─────────────────
    if (req.method === 'GET' && url.pathname === '/debug/token-exchange') {
      const record = await enforcePerimeter(req);
      if (!record) return send(res, 401, { error: 'invalid_token' });
      const { jwt } = exchangeOpaqueToJwt(record);
      log(
        'DEBUG exchange performed for learner inspection (production would NEVER expose this)',
      );
      return send(res, 200, {
        _warning:
          'DEBUG-ONLY endpoint: intentionally reveals the internal JWT (breaks Invariant #1) so you can observe the exchange.',
        opaque_token: record.token,
        internal_jwt: jwt,
        decoded_jwt: decodeJwtUnchecked(jwt),
        internal_jwt_ttl_seconds: INTERNAL_JWT_TTL_SECONDS,
      });
    }

    // ── proxied API: /v1/models ──────────────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/v1/models') {
      const record = await enforcePerimeter(req);
      if (!record) return send(res, 401, { error: 'invalid_token' });
      const { jwt, claims } = exchangeOpaqueToJwt(record);
      log(
        `PHANTOM EXCHANGE ${mask(record.token)} → JWT (sub=${claims.sub}, expires in ${INTERNAL_JWT_TTL_SECONDS}s)`,
      );
      const upstream = await forwardToPromptService('/models', 'GET', jwt);
      log(`← prompt-service responded ${upstream.status}`);
      return send(res, upstream.status, upstream.body);
    }

    // ── proxied API: /v1/completions ─────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/v1/completions') {
      const record = await enforcePerimeter(req);
      if (!record) return send(res, 401, { error: 'invalid_token' });
      const body = await readJson(req);
      // Exchange FIRST, then forward — observe in the log: the phantom swap already
      // happened before anyone cared whether prompt-service even exists.
      const { jwt, claims } = exchangeOpaqueToJwt(record);
      log(
        `PHANTOM EXCHANGE ${mask(record.token)} → JWT (sub=${claims.sub}, model=${String(body.model ?? '?')}, expires in ${INTERNAL_JWT_TTL_SECONDS}s)`,
      );
      const upstream = await forwardToPromptService(
        '/completions',
        'POST',
        jwt,
        body,
      );
      log(`← prompt-service responded ${upstream.status}`);
      return send(res, upstream.status, upstream.body);
    }

    return send(res, 404, { error: 'not_found', route });
  } catch (error) {
    log(`ERROR on ${route}: ${(error as Error).message}`);
    return send(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, () => {
  log(`API gateway listening on :${PORT} (edge zone)`);
  log(
    `forwarding /v1/* → ${PROMPT_SERVICE_URL} with rewritten Authorization header`,
  );
  if (Number(process.env.INTROSPECTION_DELAY_MS ?? 0) > 0) {
    log(
      `INTROSPECTION_DELAY_MS=${process.env.INTROSPECTION_DELAY_MS} — every request now pays a simulated store round-trip`,
    );
  }
});
