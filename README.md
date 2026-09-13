# Phantom Token Pattern Lab

A hands-on concept lab exploring the **Phantom Token Pattern** (OAuth 2.0 token exchange at
the API gateway): **opaque, revocable tokens at the public edge** translated into
**short-lived, signed JWTs inside a zero-trust microservice mesh** — themed as an AI API
gateway (`sk_live_...` keys, model allow-lists, usage quotas).

Built from scratch on Node.js standard libraries only (`node:crypto`, `node:http`) —
no JWT library, no framework, no Docker. Every signature, header, and byte is meant to
be readable.

---

## What Are We Learning?

1. **Stateless vs stateful tokens** — where the "truth" of an identity lives, and what
   that costs (JWT: truth inside the token, verified by math; opaque: truth in a store,
   verified by lookup).
2. **Zero-trust microservices with JWTs** — every service verifies the gateway's
   signature locally, in memory, with zero database hops; identity cannot be asserted
   by headers or hearsay.
3. **Gateway-based token exchange** — the client only ever holds an opaque credential;
   the internal JWT is minted at the perimeter and never leaves the private zone.

---

## Why Does This Exist? — The Distributed Auth Dilemma

| Naive approach | What breaks at scale |
|---|---|
| **A. Pure JWT to public clients** | Revocation paradox — you cannot un-issue a self-contained token without blacklists everywhere. Internal claims (ids, roles, tiers) leak to the browser. |
| **B. Pure opaque tokens everywhere** | Every service introspects the auth store on every call → N× load multiplier, cascading failure, tight coupling to the auth DB. |

The Phantom Token Pattern takes the best of both:

```
                       EXTERNAL (untrusted)     │     INTERNAL (zero-trust mesh)
                                                │
  Client ── Bearer sk_live_… ──▶  API GATEWAY   │
                                  │ introspect  │  (once, at the perimeter)
                                  │ mint JWT    │  (2-min EdDSA, private key)
                                  ▼             │
                            prompt-service ─────┼── same JWT ──▶ quota-service
                            (verify locally,    │              (verify locally,
                             0.0x ms CPU)       │               0.0x ms CPU)
```

The client never sees the JWT and its claims. The services never query an auth database.

---

## Mental Model

> **Booking code vs boarding hologram.**
>
> The `sk_live_...` key is a **booking reference**: random characters that mean nothing
> by themselves — the airline's reservation system (the token store) is the only place
> that knows `K8X2PL → Athalla, seat 12A`. Deleting that one row revokes it instantly.
>
> The internal JWT is a **stamped internal pass**: readable by anyone (it is not
> encrypted), but carrying a hologram only HQ's master plate (the gateway's private key)
> can press. Every checkpoint inside owns a cheap UV lamp (the public key) and verifies
> it in microseconds — no phone calls to HQ, ever.

---

## Architecture

Three services, one asymmetric keypair:

| Service | Port | Zone | Responsibility |
|---|---:|---|---|
| `api-gateway` | 3000 | edge | login/logout, opaque token store, **introspection + JWT minting**, reverse proxy |
| `prompt-service` | 3001 | internal | verifies JWT locally, enforces `allowed_models` from claims, propagates JWT |
| `quota-service` | 3002 | internal | verifies JWT locally, deducts credits (business state) |

Key placement *is* the architecture:

```
keys/gateway.private.pem   → loaded ONLY by the gateway (minting)
keys/gateway.public.pem    → loaded by every internal service (verifying)
```

A downstream service is structurally incapable of forging a token: it never touches the
private key. `verify()` can never produce a signature, no matter how many times an
attacker calls it.

### The life of one request

```
1. client            ── POST /v1/completions, Bearer sk_live_… ──▶ gateway
2. gateway           introspects the store ONCE      (stateful, ~ms)
3. gateway           mints a 2-minute EdDSA JWT      (private key)
4. gateway           ── Bearer eyJ… ──▶ prompt-service
5. prompt-service    verifies signature locally      (stateless, 0.0x ms)
6. prompt-service    checks allowed_models FROM CLAIMS (no DB)
7. prompt-service    ── same JWT ──▶ quota-service
8. quota-service     verifies signature AGAIN, independently
9. quota-service     deducts 1 credit, returns remaining
```

Watch it live: each service logs a colored line, so one client request appears as
`[gateway]` → `[prompt-service]` → `[quota-service]` in a single terminal.

---

## Prerequisites

- Node.js ≥ 18 (uses global `fetch`, `base64url`, Ed25519)
- npm

No runtime dependencies — the lab runs entirely on Node standard libraries.
Dev dependencies: `tsx`, `typescript`, `@types/node`.

---

## Run the Project

```bash
npm install
npm run start:all
```

The runner starts all three services, health-gates them via `/healthz`, prefixes every
log line with the service color, and kills everything on `Ctrl+C`. The Ed25519 keypair
is generated automatically into `keys/` on first run (git-ignored).

Mock accounts (clearly fake, for the lab only):

| username | password | tier | allowed models | quota |
|---|---|---|---|---:|
| `athalla` | `secret` | enterprise | gpt-4o, claude-sonnet-5, llama-3.1-405b | 5000 |
| `demo` | `secret` | free | llama-3.1-8b | 25 |

First call:

```bash
TOKEN=$(curl -s -X POST localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"athalla","password":"secret"}' \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')

curl -s -X POST localhost:3000/v1/completions \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"Explain the phantom token pattern."}'
```

Useful endpoints: `GET /debug/token-exchange` (see both token species side by side —
debug-only, intentionally violates invariant #1 for learning), `GET /stats` on the
internal services (request/verify/spoof counters).

---

## The Experiments

| # | Command | Claim it proves |
|---|---|---|
| E1 | `bash experiments/01-happy-path.sh` | Opaque and JWT stay cleanly separated end-to-end; the phantom exchange is visible |
| E2 | `bash experiments/02-revocation.sh` | Logout revokes instantly at the perimeter — downstream counters prove **zero** internal requests afterward |
| E3 | `bash experiments/03-anti-spoofing.sh` | Forged `X-User-*` headers, a tampered-but-well-formed JWT, and an `alg:none` forgery all die at 401 |
| E4 | `npm run test:benchmark` | Local signature verification (~0.0x ms) vs a store round-trip (~ms) — why the internal mesh scales |

Or run E1–E3 in sequence: `npm run test:experiments`.

E3's attack B is the deepest: the attacker takes a **legitimate** JWT, rewrites the
payload (`sub`, `tier`), keeps the valid signature — and still gets 401
`bad_signature`, because the signature covers the exact bytes of the encoded payload.

---

## Alternatives

| Approach | State | Token carries data? | Revocation | Validation cost | Typical fit |
|---|---|---|---|---|---|
| Pure JWT to clients | none | yes (readable) | hard (blacklists) | local, cheap | stateless APIs, tolerant logout delay |
| Pure opaque everywhere | per-service introspection | no | trivial | network hop per service per call | small monolith-ish systems |
| **Phantom token** | store at edge only | external: no / internal: yes | instant, at the perimeter | one introspection + N local verifies | microservices + strict revocation |

If you optimize for **simplicity** → opaque-only. For **zero infra** → JWT-only.
For **instant revocation AND internal speed** → the pattern in this lab.

---

## Trade-offs

**We gain:** instant edge revocation; internal claims never exposed to clients;
microsecond-scale internal auth; strict zero-trust compliance.

**We lose / add:** the gateway is now a critical-path component and a key custodian;
token translation adds perimeter latency (mitigated by introspection caching);
operational complexity (key management, rotation).

**Unnecessary when:** you run a modular monolith, a simple two-tier app, or any system
where an indexed DB lookup is already <0.5 ms. Don't adopt a gateway pattern to solve
a problem you don't have.

---

## Production Considerations

| Lab | Production |
|---|---|
| In-memory `Map` token store | Redis / DynamoDB with native TTL (sliding expiration ≈ one `EXPIRE`), DB for audit |
| Shared-folder PEM keys | **JWKS** endpoint (`/.well-known/jwks.json`) with `kid` rotation; private key in KMS/HSM (non-exportable) |
| Hand-rolled JWT code | audited libraries (`jose`, `jsonwebtoken`) or mesh filters (Envoy JWT authn, Istio `RequestAuthentication`) |
| Plain HTTP on localhost | mTLS service mesh, private subnets |
| Gateway = auth server + proxy in one process | dedicated Authorization Server (Keycloak/Auth0/Cognito) + edge gateway |
| Bearer-only tokens | sender-constrained tokens (DPoP, mTLS-bound) where theft matters |
| Long-lived opaque token | sliding expiration + absolute cap; refresh-token rotation with reuse detection |

Also worth knowing: never store raw opaque tokens in the store — hash them (SHA-256 is
enough for high-entropy tokens) so a database dump cannot replay sessions.

---

## What We Learned

1. **Where the truth lives decides everything** — JWT puts it in the token (stateless,
   hard to revoke); opaque puts it in a store (revocable, needs a lookup). The phantom
   pattern assigns each side the zone where its strengths matter.
2. **Revocation is a consequence, not a feature** — deleting one `Map` entry locks a
   user out everywhere *because* the token itself was meaningless.
3. **The signature covers the encoded bytes** — `header.payload` exactly as they appear
   on the wire; a well-formed JSON edit still breaks verification.
4. **Trust is never transferred, only proven** — quota-service re-verifies the same JWT
   that prompt-service already verified; one compromised service must not open the mesh.
5. **Authorization can travel in claims** — `allowed_models` was born in the token
   store, minted by the translator, and enforced 0-DB-lookups later in prompt-service.
6. **Auth state and business state are different animals** — identity is stateless
   inside the mesh; the credit balance is quota-service's own stateful domain.
7. **Statefulness is also an observability superpower** — every opaque-token use touches
   the store: impossible-travel and anomaly detection get a natural checkpoint.
8. **The import graph encodes the security model** — services can only load the public
   key; forgery is not forbidden, it is *impossible*.

---

## Further Exploration

- Add **sliding expiration** to the token store (one line in `introspectToken`) and feel
  the revocation-latency trade-off by tuning the TTL.
- Implement a **JWKS endpoint** on the gateway and make services fetch + cache the
  public key with `kid` rotation.
- Add **mTLS** between the services (or a service mesh) and re-run E3.
- Issue a **refresh token** alongside the opaque token and rotate it on use.
- Swap the hand-rolled JWT for `jose` and compare — what did the library hide?
- Try `INTROSPECTION_DELAY_MS=2 npm run start:gateway` and re-run E4's reasoning.

---

*Built in four implementation phases (crypto core → gateway → services → experiments),
each gated by a test. This lab is for learning — it is deliberately not production code.*
