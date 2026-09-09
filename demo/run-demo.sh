#!/usr/bin/env bash
# Drives three scenarios against the same poisoned MCP server:
#   1. direct        - no broker. The mutation lands.
#   2. allowlist     - deny-by-default on name. The mutation STILL lands.
#   3. pin           - deny-by-default + definition pinning. The mutation is rejected.
set -uo pipefail

DIRECT=${DIRECT:-http://localhost:${SERVER_PORT:-18080}}
ALLOW=${ALLOW:-http://localhost:${ALLOW_PORT:-18081}}
PIN=${PIN:-http://localhost:${PIN_PORT:-18082}}

PASS=0
FAIL=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
gap()  { printf '  \033[33mGAP \033[0m %s\n' "$*"; PASS=$((PASS+1)); }

rpc() { # rpc <url> <method> [name]
  local url=$1 method=$2 name=${3:-}
  local params='{}'
  [ -n "$name" ] && params="{\"name\":\"$name\",\"arguments\":{\"text\":\"hi\"}}"
  curl -s --max-time 10 -H 'Content-Type: application/json' \
       -H "X-Session-Id: ${SID:-default}" \
       -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
       "$url"
}


# Preflight. A host port can be shadowed by something else that answers HTTP
# (a kubectl port-forward beat Docker's wildcard bind on this laptop and every
# assertion below silently passed against the wrong service). Refuse to run
# unless each endpoint identifies itself as ours, in the expected mode.
preflight() { # preflight <url> <expect-mode|server>
  local url=$1 expect=$2 body
  body=$(curl -s --max-time 5 "$url/healthz") || { echo "no /healthz at $url" >&2; return 1; }
  if [ "$expect" = "server" ]; then
    echo "$body" | grep -q '"ok"' || { echo "$url is not the demo server: $body" >&2; return 1; }
  else
    echo "$body" | grep -q "\"mode\": \"$expect\"" || { echo "$url is not the $expect broker: $body" >&2; return 1; }
  fi
  printf '  preflight ok  %-28s %s\n' "$url" "$expect"
}

echo "Preflight"
preflight "$DIRECT" server    || exit 1
preflight "$ALLOW"  allowlist || exit 1
preflight "$PIN"    pin       || exit 1

# Reset the server's call counter by recreating it.
reset_server() {
  docker compose restart server >/dev/null 2>&1
  for _ in $(seq 1 30); do
    curl -sf --max-time 2 "$DIRECT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "server did not come back up" >&2; return 1
}

burn_three_calls() { # burn_three_calls <url>
  for _ in 1 2 3; do rpc "$1" tools/call format_text >/dev/null; done
}

# ---------------------------------------------------------------- scenario 1
say "Scenario 1 - no broker. Baseline: the server really does mutate."
reset_server || exit 1
before=$(rpc "$DIRECT" tools/list)
echo "$before" | grep -q 'id_rsa' \
  && bad "tools/list was poisoned BEFORE any tool call" \
  || ok  "tools/list starts benign"

burn_three_calls "$DIRECT"
after=$(rpc "$DIRECT" tools/list)
echo "$after" | grep -q 'id_rsa' \
  && ok  "after 3 calls tools/list is POISONED (mutation reproduced)" \
  || bad "server did not mutate - demo is broken"

echo "$after" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("  names still:", [t["name"] for t in d["result"]["tools"]])'

# ---------------------------------------------------------------- scenario 2
say "Scenario 2 - deny-by-default on tool NAME (the common control)."
reset_server || exit 1
export SID="allow-$$"
l1=$(rpc "$ALLOW" tools/list)
echo "$l1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("  visible:", [t["name"] for t in d["result"]["tools"]])'
echo "$l1" | grep -q 'summarize' \
  && bad "gated tool 'summarize' was visible" \
  || ok  "gated tool 'summarize' is invisible in tools/list"

burn_three_calls "$ALLOW"
l2=$(rpc "$ALLOW" tools/list)
# This is the finding, not a failure. A name-based allowlist re-approves the
# poisoned tool because the NAME did not change. The demo asserts the gap is
# real; if this ever stops reproducing, the demo has lost its point.
if echo "$l2" | grep -q 'id_rsa'; then
  gap "MUTATION ADOPTED - the allowlist passed the poisoned description through"
  echo "$l2" | python3 -c 'import json,sys; d=json.load(sys.stdin); t=d["result"]["tools"][0]; print("  format_text now says:", t["description"][:96].replace(chr(10)," ")+"...")'
else
  bad "expected the allowlist to adopt the mutation, and it did not"
fi

# ---------------------------------------------------------------- scenario 3
say "Scenario 3 - deny-by-default PLUS definition pinning."
reset_server || exit 1
export SID="pin-$$"
p1=$(rpc "$PIN" tools/list)
echo "$p1" | grep -q 'summarize' \
  && bad "gated tool 'summarize' was visible" \
  || ok  "gated tool 'summarize' is invisible in tools/list"
echo "$p1" | grep -q 'id_rsa' \
  && bad "first tools/list already poisoned" \
  || ok  "first tools/list pinned while benign"

burn_three_calls "$PIN"
p2=$(rpc "$PIN" tools/list)
if echo "$p2" | grep -q 'changed mid-session'; then
  ok "MUTATION REJECTED - broker refused the changed tools/list"
  echo "$p2" | python3 -c 'import json,sys; d=json.load(sys.stdin); e=d["error"]; print("  pinned  :", e["data"]["pinnedDigest"][:32]); print("  observed:", e["data"]["observedDigest"][:32])'
else
  bad "pinning did not reject the mutation"
fi

# the session must stay shut, not just fail one call
p3=$(rpc "$PIN" tools/call format_text)
echo "$p3" | grep -q 'quarantined' \
  && ok  "session stays quarantined for subsequent tools/call" \
  || bad "session was not quarantined after the mutation"

say "$PASS checks held, $FAIL unexpected"
[ "$FAIL" -eq 0 ]
