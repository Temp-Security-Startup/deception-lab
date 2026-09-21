#!/usr/bin/env python3
"""Deterministic harness for the ChainDrop-style registry-worm estate.

Models an npm preinstall payload (worm.py, a harmless stand-in) executing on a build runner
that holds package/cloud credentials, then republishing a package. Three arms:

  baseline   runner credential file holds the REAL publish token -> harvest, exfil, real republish
  rak        run the install payload under a rak-agent-shaped policy (exec allowlist, file deny
             on the credential dir, egress allowlist to the registry only) -> harvest and
             exfil are kernel-denied, so the worm has no token
  deception  the runner's credential file holds a CANARY token; the real registry routes a
             canary publish to the decoy (route-bound), real packages untouched, tripwire fires

No Docker, no model calls. Builds rakwrap (Landlock) from the shared source.
"""
import http.client, json, os, shutil, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("CHAIN_BASE", "/tmp/chaindrop-rerun")
REG_PORT, DECOY_PORT = 18100, 18101
REAL_TOKEN, CANARY_TOKEN = "REAL-PUBLISH-TOKEN", "CANARY-NPM-TOKEN-7f3a"
PROCS = []
PASS, FAIL = [], []


def build():
    for d in ("pkg", "creds_real", "creds_canary", "exfil"):
        os.makedirs(os.path.join(BASE, d), exist_ok=True)
    shutil.copy(os.path.join(HERE, "worm.py"), os.path.join(BASE, "pkg", "worm.py"))
    subprocess.run(["cc", "-O2", "-o", os.path.join(BASE, "rakwrap"),
                    os.path.join(HERE, "rakwrap.c")], check=True)
    open(os.path.join(BASE, "creds_real", "npmrc"), "w").write(
        f"//registry.acme.internal/:_authToken={REAL_TOKEN}\n")
    open(os.path.join(BASE, "creds_real", "aws_credentials"), "w").write(
        "[default]\naws_access_key_id = AKIA-REAL-DO-NOT-LEAK\n")
    open(os.path.join(BASE, "creds_canary", "npmrc"), "w").write(
        f"//registry.acme.internal/:_authToken={CANARY_TOKEN}\n")


def start_registries():
    global PROCS
    stop()
    real = subprocess.Popen([sys.executable, os.path.join(HERE, "registry.py")],
                            env=dict(os.environ, PORT=str(REG_PORT), DECOY="0",
                                     REAL_TOKEN=REAL_TOKEN, DECOY_URL=f"http://127.0.0.1:{DECOY_PORT}"),
                            stdout=open(os.path.join(BASE, "registry-real.log"), "w"), stderr=subprocess.STDOUT)
    decoy = subprocess.Popen([sys.executable, os.path.join(HERE, "registry.py")],
                             env=dict(os.environ, PORT=str(DECOY_PORT), DECOY="1",
                                      REAL_TOKEN=REAL_TOKEN),
                             stdout=open(os.path.join(BASE, "registry-decoy.log"), "w"), stderr=subprocess.STDOUT)
    PROCS = [real, decoy]
    for _ in range(50):
        if state(REG_PORT) is not None and state(DECOY_PORT) is not None:
            return True
        time.sleep(0.2)
    return False


def stop():
    global PROCS
    for p in PROCS:
        p.send_signal(signal.SIGTERM)
    for p in PROCS:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    PROCS = []
    time.sleep(0.3)


def state(port):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/state"); r = c.getresponse(); d = r.read()
        return json.loads(d)
    except Exception:
        return None


def reset():
    for port in (REG_PORT, DECOY_PORT):
        try:
            http.client.HTTPConnection("127.0.0.1", port, timeout=5).request("GET", "/reset") if False else None
        except Exception:
            pass
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/reset"); c.getresponse().read()
        except Exception:
            pass


def run_worm(cred_dir, confined=False):
    """Simulate `npm install` running the package preinstall hook."""
    env = dict(os.environ, REGISTRY_URL=f"http://127.0.0.1:{REG_PORT}",
               CRED_DIR=os.path.join(BASE, cred_dir), EXFIL_DIR=os.path.join(BASE, "exfil"),
               PKG="@acme/leftpad")
    if confined:
        env.update(RAK_ALLOW=f"/usr:/bin:/lib:/lib64:/etc:/dev:{BASE}/pkg",
                   RAK_NET="allow", RAK_PORTS=str(REG_PORT))
        cmd = [os.path.join(BASE, "rakwrap"), sys.executable, os.path.join(BASE, "pkg", "worm.py")]
    else:
        cmd = [sys.executable, os.path.join(BASE, "pkg", "worm.py")]
    p = subprocess.run(cmd, env=env, cwd=os.path.join(BASE, "pkg"), capture_output=True, text=True, timeout=30)
    for line in reversed(p.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            continue
    return {"raw": p.stdout[-300:], "err": p.stderr[-300:]}


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def main():
    shutil.rmtree(BASE, ignore_errors=True)
    build()
    print("== chaindrop-style registry-worm estate ==")
    check("registries come up", start_registries())

    print("== baseline: install hook harvests the real token and republishes ==")
    reset()
    r = run_worm("creds_real", confined=False)
    check("worm read runner credentials", len(r.get("read", [])) > 0, str(r))
    check("worm wrote loot", r.get("exfil") == "yes", str(r))
    check("worm republished to the REAL registry", "@acme/core" in str(r.get("publish", ""))
          and r.get("publish_tag") == "real", str(r))
    check("real registry recorded the poisoned release",
          any(p.get("name") == "@acme/core" for p in (state(REG_PORT) or {}).get("publishes", [])),
          str((state(REG_PORT) or {}).get("publishes")))

    print("== rak: install hook contained (no harvest, no exfil, no republish) ==")
    reset()
    r = run_worm("creds_real", confined=True)
    print("    worm result:", json.dumps(r)[:220])
    check("credential harvest denied", r.get("read") == [], str(r))
    check("exfil write denied", r.get("exfil") != "yes", str(r))
    check("no publish (no token harvested)", r.get("publish") in ("no", "ERR:HTTPError"), str(r))
    check("real registry has no poisoned release",
          not any(p.get("name") == "@acme/core" for p in (state(REG_PORT) or {}).get("publishes", [])),
          str((state(REG_PORT) or {}).get("publishes")))

    print("== deception: canary token routes the publish to the decoy ==")
    reset()
    r = run_worm("creds_canary", confined=False)
    print("    worm result:", json.dumps(r)[:220])
    rs, ds = state(REG_PORT) or {}, state(DECOY_PORT) or {}
    check("worm thinks it republished", "@acme/core" in str(r.get("publish", "")), str(r))
    check("published into the MAPLEPOT", any(p.get("name") == "@acme/core" for p in ds.get("publishes", [])),
          str(ds.get("publishes")))
    check("REAL registry has no poisoned release",
          not any(p.get("name") == "@acme/core" for p in rs.get("publishes", [])), str(rs.get("publishes")))
    check("canary tripwire fired on the real registry", len(rs.get("canary_hits", [])) > 0,
          str(rs.get("canary_hits")))

    stop()
    print(f"\n== RESULT: {len(PASS)} passed, {len(FAIL)} failed ==")
    if FAIL:
        print("  FAILED:", FAIL); return 1
    print("  ChainDrop-style estate verified: baseline lands, rak contains, deception diverts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())