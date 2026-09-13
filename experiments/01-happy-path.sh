#!/usr/bin/env bash
# E1 — HAPPY PATH: login → opaque token → phantom exchange → full chain → 200.
# Proves: external opaque token and internal JWT stay cleanly separated end-to-end.
set -u
BASE="${BASE:-http://localhost:3000}"

bold()  { printf '\033[1m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }

# Tiny JSON getter:  jget 'a.b'  <<< '{"a":{"b":42}}'   → 42
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

bold "== E1: HAPPY PATH =="
echo "target: ${BASE}"

curl -fsS "${BASE}/healthz" >/dev/null 2>&1 \
  || { red "❌ gateway not running — start it first (npm run start:all)"; exit 1; }
green "gateway up"

# 1. login → opaque token (and nothing else — invariant #1)
LOGIN=$(curl -s -X POST "${BASE}/auth/login" -H 'content-type: application/json' \
  -d '{"username":"athalla","password":"secret"}')
TOKEN=$(echo "$LOGIN" | jget token)
[ -n "$TOKEN" ] || { red "❌ login failed: ${LOGIN}"; exit 1; }
echo "opaque token issued : ${TOKEN:0:16}…"

# 2. full chain through the mesh
RESP=$(curl -s -X POST "${BASE}/v1/completions" -H "Authorization: Bearer ${TOKEN}" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"Explain the phantom token pattern."}')
SUB=$(echo "$RESP" | jget sub)
QUOTA=$(echo "$RESP" | jget quota.remaining)
TEXT=$(echo "$RESP" | jget 'choices.0.text')

if [ "$SUB" = "dev_99" ] && [ -n "$QUOTA" ]; then
  green "✅ completion for sub=${SUB} — quota remaining=${QUOTA}"
  echo "   ${TEXT:0:76}…"
else
  red "❌ unexpected response: ${RESP}"; exit 1
fi

# 3. witness the phantom exchange itself
EXCH=$(curl -s "${BASE}/debug/token-exchange" -H "Authorization: Bearer ${TOKEN}")
JWT=$(echo "$EXCH" | jget internal_jwt)
case "$JWT" in
  eyJ*) green "✅ phantom exchange : ${TOKEN:0:12}… → ${JWT:0:28}…" ;;
  *)    red "❌ no JWT from debug endpoint"; exit 1 ;;
esac

bold "E1 PASSED"
