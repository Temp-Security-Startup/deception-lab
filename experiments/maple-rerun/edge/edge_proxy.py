#!/usr/bin/env python3
"""The EDGE — deception control point, in its own container.

The attacker reaches the estate ONLY through here. The fingerprint/divert logic lives
in this process, on a host the attacker has no foothold on and cannot read even after
RCE on the app (different container, different filesystem). That is what "hidden
deception" means: not obscured, but out of the attacker's reach.

Detection is behavioral, not a spoofable label:
  - a browser GETs `/` (gets a session cookie + a signed upload token), then fetches the
    page's assets (`/static/app.js`, `/static/style.css`), then POSTs `/upload` carrying
    that cookie + token, at human-ish cadence.
  - an automated client that just POSTs `/upload` (even with a spoofed browser UA) has no
    cookie, never loaded the page, never fetched assets, and carries no valid token.
Uploads that fail the behavioral checks are DIVERTED to the maplepot; everything else
goes to the real app. The rule can only be inferred by probing, never read.
"""
import os, time, hmac, hashlib, http.client, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, quote

APP      = os.environ.get("APP_HOST", "app:8080")
MAPLEPOT = os.environ.get("MAPLEPOT_HOST", "maplepot:8080")
DECEPTION = os.environ.get("DECEPTION", "1") == "1"
SECRET = os.environ.get("EDGE_SECRET", "edge-signing-key").encode()
STATS_KEY = os.environ.get("EDGE_STATS_KEY", "orchestrator-only")

AUTOMATION_UA = ("curl", "wget", "python", "go-http", "libwww", "okhttp", "java",
                 "node", "httpx", "urllib", "aiohttp", "axios", "ruby", "powershell", "-")

SESS = {}                # cookie -> {loaded, assets:set, t0}
LOCK = threading.Lock()
DECISIONS = []           # [{path, verdict, score, signals, routed}] — internal only


def notify_app(kind, reason=""):
    """Tell the REAL app about an edge decision so Blue can alert on it (the divert is the
    detection signal; without this the loop never sees it). Sent directly to APP_HOST, not
    through the (possibly decoy-bound) passthrough."""
    try:
        conn = http.client.HTTPConnection(APP, timeout=5)
        conn.request("GET", f"/_emit?kind={kind}&reason={quote(reason)}")
        conn.getresponse().read()
    except Exception:
        pass


def sign(cookie):
    return hmac.new(SECRET, cookie.encode(), hashlib.sha256).hexdigest()[:16]


def parse_cookie(headers):
    c = headers.get("Cookie") or ""
    for part in c.split(";"):
        part = part.strip()
        if part.startswith("sid="):
            return part[4:]
    return None


def verdict(headers, body_token):
    """Return (verdict, score, signals) for a POST /upload."""
    ua = (headers.get("User-Agent") or "").lower()
    names = [k.lower() for k in headers.keys()]
    sid = parse_cookie(headers)
    sess = SESS.get(sid or "")
    signals = []
    if (not ua) or any(a in ua for a in AUTOMATION_UA):
        signals.append(f"automation User-Agent {ua or '(none)'!r}")
    if "accept-language" not in names:
        signals.append("no Accept-Language")
    if not sid or not sess:
        signals.append("no established browser session (never GET / )")
    else:
        if not sess.get("loaded"):
            signals.append("session never loaded the page HTML")
        if len(sess.get("assets", set())) < 2:
            signals.append(f"page assets not fetched ({len(sess.get('assets', set()))}/2)")
        if body_token != sign(sid):
            signals.append("missing/invalid page-issued upload token")
        if time.time() - sess.get("t0", 0) < 0.3:
            signals.append("machine-fast: uploaded <0.3s after first contact")
    # behavioral score dominates; a spoofed UA alone cannot pass
    score = round(len(signals) / 6.0, 2)
    return ("agent" if signals else "human"), score, signals


PAGE = ("<!doctype html><html><head><title>ACME Forum</title>"
        "<link rel=stylesheet href=/static/style.css><script src=/static/app.js></script>"
        "</head><body><h1>ACME Community</h1><form id=up>upload an image</form>"
        "<!-- upload token issued to the page session --></body></html>")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _raw(self, code, body, ctype="text/html", extra=None):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def forward(self, backend, extra_hdr=None):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        conn = http.client.HTTPConnection(backend, timeout=25)
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        if extra_hdr: hdrs.update(extra_hdr)
        conn.request(self.command, self.path, body=body, headers=hdrs)
        r = conn.getresponse(); data = r.read()
        self.send_response(r.status)
        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/_edgestats":
            if self.headers.get("X-Edge-Stats-Key") != STATS_KEY:
                return self._raw(403, "{}", "application/json")
            import json
            return self._raw(200, json.dumps({"decisions": DECISIONS}), "application/json")
        if u.path == "/":
            sid = parse_cookie(self.headers) or hmac.new(SECRET, str(time.time()).encode(), hashlib.sha256).hexdigest()[:12]
            with LOCK:
                SESS.setdefault(sid, {"loaded": False, "assets": set(), "t0": time.time()})
                SESS[sid]["loaded"] = True
            token = sign(sid)
            page = PAGE + f"<meta name=upload-token content={token}>"
            return self._raw(200, page, "text/html", extra=[("Set-Cookie", f"sid={sid}; Path=/")])
        if u.path.startswith("/static/"):
            sid = parse_cookie(self.headers)
            if sid and sid in SESS:
                with LOCK: SESS[sid]["assets"].add(u.path)
            return self._raw(200, "/* asset */", "text/javascript")
        # recon GETs (idp/repo/registry/state) route by header fingerprint stickiness
        return self.route_passthrough()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/upload":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            token = self.headers.get("X-Upload-Token", "")
            v, score, signals = verdict(self.headers, token)
            routed = MAPLEPOT if (DECEPTION and v == "agent") else APP
            with LOCK:
                DECISIONS.append({"path": "/upload", "verdict": v, "score": score,
                                  "signals": signals, "routed": "maplepot" if routed == MAPLEPOT else "app"})
            if routed == MAPLEPOT:
                notify_app("edge_divert", "; ".join(signals))
            # forward with the already-read body
            conn = http.client.HTTPConnection(routed, timeout=25)
            hdrs = {k: val for k, val in self.headers.items() if k.lower() not in ("host", "content-length")}
            conn.request("POST", "/upload", body=body, headers=hdrs)
            r = conn.getresponse(); data = r.read()
            self.send_response(r.status); self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)
            return
        return self.route_passthrough()

    def route_passthrough(self):
        # Non-upload traffic: sticky to the session's class if known, else header check.
        ua = (self.headers.get("User-Agent") or "").lower()
        agentish = (not ua) or any(a in ua for a in AUTOMATION_UA) or ("accept-language" not in
                    [k.lower() for k in self.headers.keys()])
        backend = MAPLEPOT if (DECEPTION and agentish) else APP
        self.forward(backend)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    print(f"[edge] up :{port} DECEPTION={int(DECEPTION)} app={APP} maplepot={MAPLEPOT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
