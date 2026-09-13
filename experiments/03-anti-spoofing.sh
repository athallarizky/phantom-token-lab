#!/usr/bin/env bash
# E3 — ANTI-SPOOFING & ZERO-TRUST: three attacks, all must fail with 401.
#   A) forged identity headers directly at the internal service
#   B) legitimate JWT with a TAMPERED payload (sub rewritten, old signature kept)
#   C) hand-crafted alg:"none" token
set -u
BASE="${BASE:-http://localhost:3000}"

bold()  { printf '\033[1m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }

jget() {
  node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c));
    process.stdin.on("end", () => {
      try {
        const v = process.argv[1].split(".").reduce((acc, k) => (acc == null ? acc : acc[k]), JSON.parse(d));
        console.log(v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : v);
      } catch { console.log(""); }
    });
  ' "$1"
}

bold "== E3: ANTI-SPOOFING =="

# ── Attack A: identity headers, no token, straight at the crown jewels ──────
CODE_A=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3002/quota/deduct \
  -H 'content-type: application/json' \
  -H 'X-User-Id: 1' -H 'X-Role: admin' -H 'X-Tenant-Id: org_evil' \
  -d '{"amount":999999}')
[ "$CODE_A" = "401" ] && green "A) forged headers rejected (401)" \
  || { red "A) expected 401, got ${CODE_A} — headers were trusted!"; exit 1; }

# ── Attack B: real JWT, tampered payload, original signature ────────────────
LOGIN=$(curl -s -X POST "${BASE}/auth/login" -H 'content-type: application/json' \
  -d '{"username":"athalla","password":"secret"}')
TOKEN=$(echo "$LOGIN" | jget token)
JWT=$(curl -s "${BASE}/debug/token-exchange" -H "Authorization: Bearer ${TOKEN}" | jget internal_jwt)
[ -n "$JWT" ] || { red "could not obtain a JWT for the attack"; exit 1; }

TAMPERED=$(node -e '
  const parts = process.argv[1].split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  payload.sub = "dev_01";          // impersonate another developer
  payload.tier = "enterprise";
  const evilPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  console.log(`${parts[0]}.${evilPayload}.${parts[2]}`); // keep the OLD signature
' "$JWT")

CODE_B=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3001/completions \
  -H "Authorization: Bearer ${TAMPERED}" -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"as someone else"}')
[ "$CODE_B" = "401" ] && green "B) tampered JWT rejected (401 bad_signature)" \
  || { red "B) expected 401, got ${CODE_B} — tampering undetected!"; exit 1; }

# ── Attack C: alg:none forgery ───────────────────────────────────────────────
FORGED=$(node -e '
  const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({
    iss: "phantom-gateway", sub: "dev_01", aud: "internal-services",
    roles: ["admin"], tier: "enterprise", allowed_models: ["gpt-4o"],
    quota_remaining: 999999, iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, jti: "forged",
  })).toString("base64url");
  console.log(`${h}.${p}.`);
')

CODE_C=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3001/completions \
  -H "Authorization: Bearer ${FORGED}" -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"no signature at all"}')
[ "$CODE_C" = "401" ] && green "C) alg:none forgery rejected (401 unsupported_alg)" \
  || { red "C) expected 401, got ${CODE_C} — unsigned token accepted!"; exit 1; }

SPOOF=$(curl -s localhost:3002/stats | jget spoof_attempts)
echo "   (quota-service spoof_attempts counter now: ${SPOOF})"

bold "E3 PASSED — identity cannot be asserted without a valid gateway signature"
