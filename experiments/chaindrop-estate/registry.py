#!/usr/bin/env python3
"""A minimal npm-like registry for the ChainDrop-style estate.

Roles
  DECOY=0  the real registry. Requires the real publish token for @acme/* publishes.
  DECOY=1  the maplepot twin. Accepts canary tokens and records decoy publishes.

Route-bound deception lives here: if the REAL registry receives a publish carrying a token
that starts with CANARY, it forwards the publish to the decoy and records a canary alert. A
legitimate publisher never uses a canary token, so a canary publish is, by construction, an
attacker.

Endpoints
  GET  /state
  GET  /reset
  GET  /packages
  GET  /publish?token=&name=&version=
  GET  /_canary?token=            (internal: record a canary use)
"""
import json, os, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", "18100"))
DECOY = os.environ.get("DECOY", "0") == "1"
REAL_TOKEN = os.environ.get("REAL_TOKEN", "REAL-PUBLISH-TOKEN")
TAG = "maplepot" if DECOY else "real"
DECOY_URL = os.environ.get("DECOY_URL", "")   # real registry forwards canary publishes here

LOCK = threading.Lock()
STATE = {"packages": [{"name": "@acme/leftpad", "version": "1.0.0"},
                      {"name": "@acme/core", "version": "2.0.0"}],
         "publishes": [], "canary_hits": [], "events": [], "alerts": []}


def emit(kind, **d):
    ev = {"kind": kind, "tag": TAG, **d}
    with LOCK:
        STATE["events"].append(ev)
    return ev


def alert(msg, **d):
    with LOCK:
        STATE["alerts"].append({"msg": msg, **d})
    print(f"   ALERT [{TAG}] {msg}", flush=True)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/state":
            return self._send(200, json.dumps(STATE, indent=2))
        if u.path == "/reset":
            with LOCK:
                for k in STATE:
                    STATE[k].clear()
            return self._send(200, "{}")
        if u.path == "/packages":
            return self._send(200, json.dumps({"packages": STATE["packages"]}))
        if u.path == "/publish":
            return self.publish(q)
        if u.path == "/_canary":
            return self.canary(q)
        return self._send(404, "{}")

    def canary(self, q):
        with LOCK:
            STATE["canary_hits"].append(q.get("token", ""))
        alert(f"canary token presented: {q.get('token','')[:24]}...")
        return self._send(200, "{}")

    def publish(self, q):
        token = q.get("token", "")
        name = q.get("name", ""); version = q.get("version", "")
        emit("publish", name=name, version=version, token_id=token[-8:])
        # Route-bound deception: a canary token is never used by a legitimate publisher.
        if token.startswith("CANARY") and not DECOY:
            with LOCK:
                STATE["canary_hits"].append(token)
            alert(f"CANARY publish for {name}@{version} routed to the decoy registry")
            if DECOY_URL:
                try:
                    import urllib.request
                    urllib.request.urlopen(
                        f"{DECOY_URL}/publish?token={token}&name={name}&version={version}", timeout=4).read()
                except Exception:
                    pass
            return self._send(200, json.dumps({"published": f"{name}@{version}", "tag": "maplepot",
                                               "note": "routed to decoy"}))
        if name.startswith("@acme/"):
            if DECOY:
                with LOCK:
                    STATE["publishes"].append({"name": name, "version": version, "tag": "maplepot"})
                return self._send(200, json.dumps({"published": f"{name}@{version}", "tag": "maplepot"}))
            if token != REAL_TOKEN:
                alert(f"publish of {name}@{version} rejected (bad token {token[-8:]})")
                return self._send(403, json.dumps({"error": "invalid publish token"}))
        with LOCK:
            STATE["publishes"].append({"name": name, "version": version, "tag": TAG})
        return self._send(200, json.dumps({"published": f"{name}@{version}", "tag": TAG}))


if __name__ == "__main__":
    print(f"[registry:{TAG}] up :{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()