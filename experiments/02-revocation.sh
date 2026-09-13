#!/usr/bin/env bash
# E2 — INSTANT REVOCATION: logout kills the token AT THE PERIMETER.
# Proves: after revocation, downstream services receive ZERO further requests.
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

bold "== E2: INSTANT REVOCATION =="

LOGIN=$(curl -s -X POST "${BASE}/auth/login" -H 'content-type: application/json' \
  -d '{"username":"athalla","password":"secret"}')
TOKEN=$(echo "$LOGIN" | jget token)
[ -n "$TOKEN" ] || { red "❌ login failed: ${LOGIN}"; exit 1; }

# 1. the token works
CODE1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/v1/completions" \
  -H "Authorization: Bearer ${TOKEN}" -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"warm-up"}')
[ "$CODE1" = "200" ] || { red "❌ pre-revocation call failed (HTTP ${CODE1})"; exit 1; }
green "pre-revocation call : 200 OK"

# 2. snapshot downstream counters BEFORE revocation
P_BEFORE=$(curl -s localhost:3001/stats | jget requests)
Q_BEFORE=$(curl -s localhost:3002/stats | jget requests)

# 3. revoke
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/auth/logout" \
  -H "Authorization: Bearer ${TOKEN}")
[ "$CODE" = "200" ] || { red "❌ logout failed (HTTP ${CODE})"; exit 1; }
echo "logout               : revoked"

# 4. same token, immediately after
CODE2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/v1/completions" \
  -H "Authorization: Bearer ${TOKEN}" -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","prompt":"should never arrive"}')
[ "$CODE2" = "401" ] || { red "❌ expected 401 after logout, got HTTP ${CODE2}"; exit 1; }
green "post-revocation call : 401 BLOCKED AT PERIMETER"

# 5. the proof: downstream counters must not have moved
P_AFTER=$(curl -s localhost:3001/stats | jget requests)
Q_AFTER=$(curl -s localhost:3002/stats | jget requests)
if [ "$P_BEFORE" = "$P_AFTER" ] && [ "$Q_BEFORE" = "$Q_AFTER" ]; then
  green "downstream untouched : prompt ${P_BEFORE}→${P_AFTER}, quota ${Q_BEFORE}→${Q_AFTER}"
else
  red "❌ downstream WAS called after revocation: prompt ${P_BEFORE}→${P_AFTER}, quota ${Q_BEFORE}→${Q_AFTER}"
  exit 1
fi

bold "E2 PASSED — the JWT revocation paradox is solved at the perimeter"
