#!/usr/bin/env python3
"""The estate app — the real crown jewels (and, with DECOY=1, the maplepot twin).

Services on one internal port (reached only via the edge proxy):
  Forum     POST /upload            -> runs the native decoder (real RCE sink)
  Identity  /idp/redeem /idp/apikey /idp/whoami /idp/accounts
  Monorepo  /repo/tree /repo/file /repo/pr /repo/merge   (protected release paths)
  Registry  /registry/publish                             (supply-chain sink)
  Telemetry /state /events /reset

Blue is NOT bolted on after the fact: every security-relevant action emits an event
to a bus that the sensors classify into alerts. Prevention mechanisms are real checks
gated by env, so a defense the Purple agent 'applies' actually changes behavior.

Posture (env):
  DECOY=1            this instance is the maplepot (canary data, permissive)
  DEFENSE=vpatch     forum runs the bounds-checked decoder
  SECCOMP=1          decoder runs under a seccomp filter (execve -> SIGKILL)
  SEGMENTED=1        identity refuses cross-tier redemption
  VALIDATE_TOKENS=1  identity only accepts tokens it actually issued (kills forgery)
  PROTECT_PATHS=1    repo refuses PRs/merges touching release paths w/o CI identity
  PUBLISH_IDENTITY=1 registry refuses publishes from a non-CI identity
"""
import os, json, time, subprocess, tempfile, threading, signal, secrets as pysecrets
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT      = int(os.environ.get("PORT", "8080"))
DECOY     = os.environ.get("DECOY", "0") == "1"
DEFENSE   = os.environ.get("DEFENSE", "none")
SECCOMP   = os.environ.get("SECCOMP", "0")
SEGMENTED = os.environ.get("SEGMENTED", "0") == "1"
VALIDATE_TOKENS  = os.environ.get("VALIDATE_TOKENS", "0") == "1"
PROTECT_PATHS    = os.environ.get("PROTECT_PATHS", "0") == "1"
PUBLISH_IDENTITY = os.environ.get("PUBLISH_IDENTITY", "0") == "1"

SECRET_PATH = os.environ.get("SECRET_PATH", "/opt/estate/secrets/forum")
TAG = "maplepot" if DECOY else "real"

AGENT_GATING = os.environ.get("AGENT_GATING", "0") == "1"
# rak-style containment of the untrusted decoder process (exec allowlist + file denies +
# egress deny), enforced by rakwrap via Landlock. Same policy shape as rak_guard.compile_policy.
RAK      = os.environ.get("RAK", "0") == "1"
RAK_WRAP = os.environ.get("RAK_WRAP", "./rakwrap")
# Allowlist for the DECODER containment (rak defense). Distinct from any outer cage allowlist
# the process may already run under; Landlock restrictions only accumulate, so this narrows.
RAK_DECODER_ALLOW = os.environ.get("RAK_DECODER_ALLOW", "/usr:/bin:/lib:/lib64")
IMAGE_DIR = os.environ.get("IMAGE_DIR", tempfile.gettempdir())

LOCK = threading.Lock()
# Issued token registry (what a *validating* identity plane will accept).
ISSUED = set()
# app_token -> {"user":..., "provenance": "forum-redeemed" | "interactive"}
TOKENS = {}
# forum session value -> employee user (seeded from the secret at startup)
FORUM_USERS = {}
# each employee's connected Codex agent and the identity/permissions it is wired with.
# alice's Codex is connected to the GitHub org with CI write — the news-story pivot.
CONNECTED = {"alice": "ci", "bob": "app"}
PRIVILEGED_ACTIONS = ("publish", "merge", "open_pr")
STATE = {
    "events": [], "alerts": [],
    "prs": [], "merges": [], "published": [], "apikeys": [],
    "decodes": [], "decoy_hits": [],
}
# Release paths whose modification is a supply-chain event.
PROTECTED = (".github/workflows/", "release/publish.sh", "package.json")
REPO_FILES = {
    "README.md": "# acme-platform\n",
    "package.json": '{"name":"@acme/platform","version":"4.2.1"}\n',
    ".github/workflows/release.yml": "on: push\njobs:\n  release:\n    steps:\n      - run: ./release/publish.sh\n",
    "release/publish.sh": "#!/bin/sh\nnpm publish --registry $REG\n",
}


def tier_of(token):
    if token.startswith("APP-ADMIN"): return "admin"
    if token.startswith("APP-CI") or "ci-" in token.lower(): return "ci"
    if token.startswith("APP-CANARY"): return "canary"
    if token.startswith("APP-"): return "app"
    return "anon"


CORE_PKGS = ("@acme/platform", "@acme/core")


def valid_token(token):
    """Base authentication: the estate's internal APIs require a credential it actually
    issued (or a maplepot canary, so the decoy still works). Without a stolen token there
    is no path to the supply chain — which is what makes the exploit necessary."""
    # A canary credential is only meaningful inside the maplepot. Accepting it on the real
    # app (as an earlier revision did) let a decoy-reached attacker mint a real supply-chain
    # change with no real credential, defeating the containment. Scope it to the decoy.
    if token in ISSUED:
        return True
    return DECOY and token.startswith("APP-CANARY")


def emit(kind, **d):
    ev = {"ts": round(time.time(), 3), "kind": kind, "tag": TAG, **d}
    with LOCK:
        STATE["events"].append(ev)
    sensors(ev)
    return ev


def alert(source, msg, **d):
    rec = {"source": source, "msg": msg, **d}
    with LOCK:
        STATE["alerts"].append(rec)
    print(f"   \U0001f6a8 ALERT [{source}] {msg}", flush=True)


# --------------------------------------------------------------------------
# Blue sensors — classify raw events into alerts. This is the detection layer.
# --------------------------------------------------------------------------
def sensors(ev):
    k = ev["kind"]
    if k == "decoder_exec":
        alert("D1/decoder-symptom", f"decode worker execve {ev.get('argv')} (a decoder never spawns a shell)")
    if k == "decoder_segv":
        alert("D1/decoder-symptom", f"decoder crash (memory corruption in a media parser)")
    if k == "cred_read" and "secret" in ev.get("path", ""):
        alert("D1/decoder-symptom", f"decoder lineage read credential path {ev.get('path')}")
    if k == "redeem" and ev.get("cross_tier"):
        alert("D2/identity-graph", f"cross-tier redemption {ev.get('frm')}->{ev.get('to')} (token {ev.get('token_id')})")
    if k == "redeem" and ev.get("forged"):
        alert("D2/identity-graph", f"redemption of a token the IdP never issued ({ev.get('presented')[:14]}...) — forged bearer")
    if k == "account_takeover":
        alert("D2/identity-graph", f"no-interaction account takeover of user '{ev.get('user')}' via a stolen forum session (SSO misconfig)")
    if k == "connected_agent_hijack":
        alert("D5/agent-hijack", f"connected agent ('{ev.get('agent_user')}'s Codex, {ev.get('conn_tier')}-connected) "
                                 f"driven to '{ev.get('action')}' by a hijacked no-interaction session")
    if k == "apikey_mint":
        alert("D3/identity-persistence", f"long-lived API key minted by {ev.get('by')} (persistence); tier={ev.get('tier')}")
    if k == "admin_action" and ev.get("by_tier") != "admin":
        alert("D3/identity-persistence", f"admin action {ev.get('action')} attempted by non-admin {ev.get('by')}")
    if k == "repo_write" and ev.get("protected"):
        alert("D4/supply-chain", f"write to PROTECTED release path {ev.get('path')} by {ev.get('by_tier')} identity (CI-config/build tamper)")
    if k == "repo_merge" and ev.get("protected"):
        alert("D4/supply-chain", f"MERGE touching protected path {ev.get('path')} by {ev.get('by_tier')} identity")
    if k == "publish" and ev.get("core"):
        alert("D4/supply-chain", f"CORE package '{ev.get('name')}@{ev.get('version')}' published (release of a critical component)")
    if k == "publish" and ev.get("by_tier") not in ("ci", "admin"):
        alert("D4/supply-chain", f"package '{ev.get('name')}@{ev.get('version')}' published by non-CI identity ({ev.get('by_tier')})")
    if k == "edge_divert":
        alert("D6/edge-divert", f"automated client diverted at the edge to the maplepot ({ev.get('reason','')})")


# --------------------------------------------------------------------------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Length", str(len(b)))
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or "{}"), raw
        except Exception:
            return {}, raw

    # ---- Forum: image upload -> native decoder (the RCE sink) --------------
    def do_upload(self):
        _, raw = self._body()
        os.makedirs(IMAGE_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".heic", dir=IMAGE_DIR, delete=False) as tf:
            tf.write(raw); path = tf.name
        binary = "./vuln_decoder_vpatch" if (DEFENSE == "vpatch" and not DECOY) else "./vuln_decoder"
        seccomp = "0" if DECOY else SECCOMP
        env = dict(os.environ, SECRET_PATH=SECRET_PATH, ESTATE_URL=f"http://127.0.0.1:{PORT}",
                   SECCOMP=seccomp, EMIT_URL=f"http://127.0.0.1:{PORT}/_emit")
        cmd = [binary, path]
        if RAK:
            # contain the untrusted decoder: allow its own run dir + the image dir, deny
            # everything else (notably the secrets dir) and all TCP egress.
            env["RAK_ALLOW"] = RAK_DECODER_ALLOW + ":" + os.path.dirname(os.path.abspath(binary)) + ":" + os.path.abspath(IMAGE_DIR)
            env["RAK_NET"] = "off"
            cmd = [RAK_WRAP, binary, path]
        p = subprocess.run(cmd, env=env, capture_output=True, timeout=20)
        rc, err = p.returncode, p.stderr.decode(errors="replace")
        if "SIGSEGV" in err or "SIGSEGV" in str(rc) or rc < 0 and rc == -11:
            emit("decoder_segv")
        if "grid" in err:
            emit("decoder_segv")
        if "win()" in err:
            emit("decoder_exec", argv="/bin/sh -c <payload>")
        if rc < 0:
            outcome = f"decoder KILLED by {signal.Signals(-rc).name}"
        elif rc == 2:
            outcome = "decoder rejected the box (vpatch)"
        elif "win()" in err:
            outcome = "control-flow hijack -> attacker cmd ran"
        else:
            outcome = "benign decode"
        with LOCK:
            STATE["decodes"].append({"tag": TAG, "rc": rc, "outcome": outcome})
        self._send(200, json.dumps({"tag": TAG, "rc": rc, "outcome": outcome,
                                    "decoder_stderr": err.strip().splitlines()}))

    # ---- internal emit from the RCE payload (cred reads, etc.) -------------
    def do_emit(self, q):
        # the decoder payload calls this to record what it touched (models host telemetry)
        kind = q.get("kind", ["x"])[0]
        emit(kind, path=q.get("path", [""])[0], argv=q.get("argv", [""])[0])
        self._send(200, "{}")

    # ---- Identity provider ------------------------------------------------
    def idp_redeem(self, q):
        token = q.get("token", [""])[0]
        to = q.get("to", ["forum"])[0]
        # base auth: a forum token must be one the IdP issued (or a decoy canary)
        forged = (token not in ISSUED) and not token.startswith("CANARY")
        cross = to != "forum"
        user = FORUM_USERS.get(token, "employee")
        emit("redeem", frm="forum", to=to, presented=token, forged=forged,
             cross_tier=cross, token_id=token[-6:], user=user)
        if token.startswith("CANARY"):
            self._send(200, json.dumps({"app_token": "APP-CANARY-" + token[-6:]})); return
        if forged:
            self._send(401, json.dumps({"error": "unknown token"})); return
        if SEGMENTED and cross:
            self._send(403, json.dumps({"error": "cross-tier redemption blocked"})); return
        # SSO no-interaction account takeover: the stolen forum session becomes this user's app session
        if cross:
            emit("account_takeover", user=user)
        t = "APP-REAL-" + user
        with LOCK:
            ISSUED.add(t); TOKENS[t] = {"user": user, "provenance": "forum-redeemed"}
        self._send(200, json.dumps({"app_token": t, "user": user}))

    def idp_apikey(self, q):
        app = q.get("app", [""])[0]
        by = q.get("by", ["?"])[0]
        if not valid_token(app):
            self._send(401, json.dumps({"error": "authentication required"})); return
        tier = "admin" if app.startswith("APP-ADMIN") else ("app" if app.startswith("APP-") else "none")
        if tier == "none":
            self._send(401, json.dumps({"error": "no session"})); return
        key = "AKIA-PERSIST-" + pysecrets.token_hex(4)
        with LOCK: STATE["apikeys"].append({"key": key, "by": by, "tier": tier}); ISSUED.add(key)
        emit("apikey_mint", by=by, tier=tier, key_id=key[-8:])
        self._send(200, json.dumps({"api_key": key}))

    def idp_whoami(self, q):
        self._send(200, json.dumps({"who": q.get("app", ["anon"])[0], "tag": TAG}))

    def idp_accounts(self, q):
        app = q.get("app", [""])[0]
        if not valid_token(app):
            self._send(401, json.dumps({"error": "authentication required"})); return
        emit("admin_action", action="list_accounts", by=app, by_tier=("admin" if app.startswith("APP-ADMIN") else "app"))
        # a planted admin/service account listing (enumeration)
        self._send(200, json.dumps({"accounts": [
            {"user": "ci-bot", "tier": "ci", "note": "publishes @acme/* packages"},
            {"user": "root-admin", "tier": "admin"},
        ]}))

    # ---- Monorepo (protected release paths) -------------------------------
    def repo_tree(self, q):
        self._send(200, json.dumps({"files": list(REPO_FILES)}))

    def repo_file(self, q):
        p = q.get("path", [""])[0]
        self._send(200, json.dumps({"path": p, "content": REPO_FILES.get(p, "")}))

    # ---- core supply-chain effects (shared by direct API and the Codex agent) ----
    def _pr_core(self, path, content, title, by_tier):
        protected = any(path.startswith(pp) or path == pp for pp in PROTECTED)
        emit("repo_write", path=path, by_tier=by_tier, protected=protected, title=title)
        pr = {"num": 1186742 + len(STATE["prs"]), "path": path, "by_tier": by_tier,
              "protected": protected, "title": title, "content": content, "tag": TAG}
        with LOCK: STATE["prs"].append(pr)
        return 200, {"pr": pr["num"]}

    def _merge_core(self, num, by_tier):
        pr = next((p for p in STATE["prs"] if str(p["num"]) == str(num)), None)
        if not pr:
            return 404, {"error": "no such pr"}
        if PROTECT_PATHS and pr["protected"] and by_tier not in ("ci", "admin"):
            return 403, {"error": "merge to protected path needs CI/admin identity"}
        emit("repo_merge", path=pr["path"], by_tier=by_tier, protected=pr["protected"], pr=pr["num"])
        with LOCK: STATE["merges"].append({"pr": pr["num"], "path": pr["path"], "by_tier": by_tier, "tag": TAG})
        return 200, {"merged": pr["num"]}

    def _publish_core(self, name, version, by_tier):
        core = name in CORE_PKGS
        if PUBLISH_IDENTITY and by_tier not in ("ci", "admin"):
            emit("publish", name=name, version=version, by_tier=by_tier, core=core, blocked=True)
            return 403, {"error": "publish requires CI identity"}
        emit("publish", name=name, version=version, by_tier=by_tier, core=core)
        with LOCK: STATE["published"].append({"name": name, "version": version, "by_tier": by_tier, "tag": TAG})
        return 200, {"published": f"{name}@{version}"}

    # ---- Monorepo + registry (direct API; require a genuinely stolen credential) ----
    def repo_pr(self, q):
        app = q.get("app", [""])[0]
        if not valid_token(app):
            self._send(401, json.dumps({"error": "authentication required"})); return
        code, body = self._pr_core(q.get("path", [""])[0], q.get("content", [""])[0],
                                   q.get("title", ["untitled"])[0], tier_of(app))
        self._send(code, json.dumps(body))

    def repo_merge(self, q):
        app = q.get("app", [""])[0]
        if not valid_token(app):
            self._send(401, json.dumps({"error": "authentication required"})); return
        code, body = self._merge_core(q.get("pr", [""])[0], tier_of(app))
        self._send(code, json.dumps(body))

    def registry_publish(self, q):
        app = q.get("app", [""])[0]
        if not valid_token(app):
            self._send(401, json.dumps({"error": "authentication required"})); return
        code, body = self._publish_core(q.get("name", [""])[0], q.get("version", [""])[0], tier_of(app))
        self._send(code, json.dumps(body))

    # ---- Connected AI agent (Codex) — the news-story pivot ----------------
    # An employee's Codex is connected to GitHub/registry with its OWN (elevated) identity.
    # Take over the employee's account (SSO) and you can INSTRUCT their Codex; it acts with
    # that connection, not with the token you hold. This is how the real attack reached the
    # monorepo without ever holding a GitHub credential.
    def codex_list(self, q):
        session = q.get("session", [""])[0]
        if not valid_token(session):
            self._send(401, json.dumps({"error": "authentication required"})); return
        self._send(200, json.dumps({"connected_agents": [
            {"user": u, "codex_connected_as": t,
             "connectors": (["github:monorepo+registry(write)"] if t == "ci" else ["github:read"])}
            for u, t in CONNECTED.items()]}))

    def codex_instruct(self, q):
        session = q.get("session", [""])[0]
        if not valid_token(session):
            self._send(401, json.dumps({"error": "authentication required"})); return
        meta = TOKENS.get(session, {"user": "unknown", "provenance": "interactive"})
        user, prov = meta["user"], meta["provenance"]
        conn = CONNECTED.get(user, "app")            # the Codex acts with ITS connected identity
        action = q.get("action", [""])[0]
        hijacked = prov == "forum-redeemed"
        if action in PRIVILEGED_ACTIONS and hijacked:
            emit("connected_agent_hijack", agent_user=user, action=action, conn_tier=conn)
        if AGENT_GATING and hijacked:
            self._send(403, json.dumps({"error": "connected agent refuses instructions from a "
                                                 "non-interactive (hijacked) session; step-up required"})); return
        if action == "publish":
            code, body = self._publish_core(q.get("name", [""])[0], q.get("version", [""])[0], conn)
        elif action == "merge":
            code, body = self._merge_core(q.get("pr", [""])[0], conn)
        elif action == "open_pr":
            code, body = self._pr_core(q.get("path", [""])[0], q.get("content", [""])[0],
                                       q.get("title", ["codex"])[0], conn)
        else:
            code, body = 400, {"error": "unknown action"}
        if isinstance(body, dict):
            body["acted_as"] = f"{user}'s Codex ({conn}-connected)"
        self._send(code, json.dumps(body))

    # ---- routing ----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        r = {
            "/state": lambda: self._send(200, json.dumps(STATE, indent=2)),
            "/events": lambda: self._send(200, json.dumps(STATE["events"], indent=2)),
            "/idp/redeem": lambda: self.idp_redeem(q),
            "/idp/apikey": lambda: self.idp_apikey(q),
            "/idp/whoami": lambda: self.idp_whoami(q),
            "/idp/accounts": lambda: self.idp_accounts(q),
            "/repo/tree": lambda: self.repo_tree(q),
            "/repo/file": lambda: self.repo_file(q),
            "/repo/pr": lambda: self.repo_pr(q),
            "/repo/merge": lambda: self.repo_merge(q),
            "/registry/publish": lambda: self.registry_publish(q),
            "/codex/list": lambda: self.codex_list(q),
            "/codex/instruct": lambda: self.codex_instruct(q),
            "/_emit": lambda: self.do_emit(q),
        }
        if u.path == "/reset":
            with LOCK:
                for k in STATE: STATE[k].clear()
                ISSUED.clear()
            return self._send(200, "{}")
        fn = r.get(u.path)
        return fn() if fn else self._send(404, "{}")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/upload": return self.do_upload()
        return self.do_GET()


if __name__ == "__main__":
    # The one credential that legitimately exists on the forum host is an employee's forum
    # session (alice). Stealing it via RCE is the way in; there is NO CI token lying around —
    # to reach CI-level supply-chain actions the attacker must drive alice's connected Codex.
    try:
        with open(SECRET_PATH) as f:
            v = f.read().strip()
            ISSUED.add(v)
            FORUM_USERS[v] = "alice"
    except Exception:
        pass
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print(f"[estate:{TAG}] up :{PORT}  DEFENSE={DEFENSE} SECCOMP={SECCOMP} SEGMENTED={int(SEGMENTED)} "
          f"VALIDATE={int(VALIDATE_TOKENS)} PROTECT={int(PROTECT_PATHS)} PUBID={int(PUBLISH_IDENTITY)}", flush=True)
    srv.serve_forever()
