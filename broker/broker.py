"""Deny-by-default MCP tool broker with definition pinning.

Two controls, deliberately separable so the demo can show that only one of them
stops a mid-session mutation:

  ALLOWLIST  (MODE=allowlist)  Deny-by-default on tool NAME. Tools that are not
                               allowed are stripped from tools/list, so the model
                               never sees them, and tools/call for them is refused.

  PINNING    (MODE=pin)        Everything the allowlist does, PLUS: the first
                               tools/list of a session is pinned by digest over
                               (name, description, inputSchema). Any later
                               tools/list whose digest differs is REJECTED rather
                               than passed through, and the session is quarantined.

The point of the demo is that ALLOWLIST alone is not enough. A name-based
allowlist re-approves a poisoned tool because the name did not change.
"""
import hashlib
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

UPSTREAM = os.environ.get("UPSTREAM", "http://server:8080")
MODE = os.environ.get("MODE", "pin")  # allowlist | pin
ALLOWED = set(
    t.strip() for t in os.environ.get("ALLOWED_TOOLS", "format_text").split(",")
    if t.strip()
)

# session id -> {"digest": str, "tools": [...]}
PINS = {}
QUARANTINED = set()


def tool_digest(tools):
    """Stable digest over the security-relevant surface of a tool list.

    Name alone is not the surface. The description is what the model reasons over,
    and the input schema is what it is invited to fill in, so both are pinned.
    """
    canon = [
        {
            "name": t.get("name"),
            "description": t.get("description"),
            "inputSchema": t.get("inputSchema"),
        }
        for t in sorted(tools, key=lambda x: x.get("name", ""))
    ]
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def upstream(payload):
    req = urllib.request.Request(
        UPSTREAM, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[broker] " + (fmt % args), flush=True)

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._send({"ok": True, "mode": MODE, "allowed": sorted(ALLOWED)})
            return
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}}, 400)
            return

        sid = self.headers.get("X-Session-Id", "default")
        method = req.get("method")
        rid = req.get("id")

        if sid in QUARANTINED:
            self._send({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32001,
                "message": "session quarantined: tool definitions changed mid-session",
            }})
            return

        if method == "tools/list":
            resp = upstream(req)
            tools = (resp.get("result") or {}).get("tools", [])

            # Control 1: deny-by-default. Gated tools never reach the model.
            visible = [t for t in tools if t.get("name") in ALLOWED]
            dropped = [t.get("name") for t in tools if t.get("name") not in ALLOWED]
            if dropped:
                print(f"[broker] denied (not in allowlist): {dropped}", flush=True)

            # Control 2: pinning. Only in MODE=pin.
            if MODE == "pin":
                digest = tool_digest(visible)
                pinned = PINS.get(sid)
                if pinned is None:
                    PINS[sid] = {"digest": digest, "tools": visible}
                    print(f"[broker] PINNED session={sid} digest={digest[:16]}",
                          flush=True)
                elif pinned["digest"] != digest:
                    QUARANTINED.add(sid)
                    print(f"[broker] REJECTED session={sid} "
                          f"pinned={pinned['digest'][:16]} "
                          f"got={digest[:16]}", flush=True)
                    self._send({"jsonrpc": "2.0", "id": rid, "error": {
                        "code": -32001,
                        "message": "tool definitions changed mid-session",
                        "data": {
                            "pinnedDigest": pinned["digest"],
                            "observedDigest": digest,
                        },
                    }})
                    return
                else:
                    print(f"[broker] pin ok session={sid} digest={digest[:16]}",
                          flush=True)

            self._send({"jsonrpc": "2.0", "id": rid, "result": {"tools": visible}})
            return

        if method == "tools/call":
            name = (req.get("params") or {}).get("name", "")
            if name not in ALLOWED:
                print(f"[broker] denied tools/call {name}", flush=True)
                self._send({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32002, "message": f"tool not allowed: {name}"}})
                return
            self._send(upstream(req))
            return

        self._send(upstream(req))


if __name__ == "__main__":
    print(f"[broker] listening on :9090 mode={MODE} allowed={sorted(ALLOWED)} "
          f"upstream={UPSTREAM}", flush=True)
    HTTPServer(("0.0.0.0", 9090), Handler).serve_forever()
