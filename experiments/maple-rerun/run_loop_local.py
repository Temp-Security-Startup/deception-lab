#!/usr/bin/env python3
"""Live-loop rerun on the Docker-free harness, with two fixes to the published methodology:

  1. UNGUIDED red prompt by default (RED_GUIDED=1 to use the original hand-holding prompt);
  2. the attacker foothold is WIPED between loops, so runs are independent (the published
     harness keeps one long-lived foothold, and its own transcripts show leftover exploit
     scripts from earlier loops).

Usage:
  python3 run_loop_local.py [n] [--guided] [--deception] [--force-rak]
"""
import json, os, shutil, sys, time
import run_local as H
import agents_local as A

MODEL = os.environ.get("RERUN_MODEL", "deepseek/deepseek-v4.1-flash")
STEPS = int(os.environ.get("RERUN_STEPS", "16"))


def reset_foothold():
    for name in os.listdir(H.FOOTHOLD):
        p = os.path.join(H.FOOTHOLD, name)
        if name in ("vuln_decoder", "vuln_decoder.c"):
            continue
        shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)


def env_for(choices, deception):
    env, dec = {}, deception
    for c in choices:
        if c == "vpatch":
            env["DEFENSE"] = "vpatch"
        elif c == "seccomp":
            env["SECCOMP"] = "1"
        elif c == "segmentation":
            env["SEGMENTED"] = "1"
        elif c == "protect_paths":
            env["PROTECT_PATHS"] = "1"
        elif c == "publish_identity":
            env["PUBLISH_IDENTITY"] = "1"
        elif c == "agent_gating":
            env["AGENT_GATING"] = "1"
        elif c == "rak":
            env.update({"RAK": "1", "RAK_WRAP": os.path.join(H.RUN, "rakwrap")})
        elif c == "deception":
            dec = True
    return env, dec


def summarize(tr):
    cmds = [t["cmd"] for t in tr if t.get("cmd")]
    fin = [t["text"] for t in tr if t.get("text")]
    return "commands:\n" + "\n".join(f"  $ {c}" for c in cmds[-12:]) + "\nconclusion:\n" + (fin[-1] if fin else "(none)")


def one_loop(idx, guided, deception_phase, force_rak, results):
    reset_foothold()
    H.start(deception=deception_phase)
    tr, u = A.red_run(model=MODEL, max_steps=STEPS, guided=guided)
    st = H.app_state(); hit = H.compromised(st)
    rec = {"idx": idx, "phase_deception": deception_phase, "guided": guided,
           "attack_compromised": hit, "attack_alerts": len(st.get("alerts", [])),
           "usage": u, "attack_cmds": [t["cmd"] for t in tr if t.get("cmd")]}
    print(f"  loop {idx:02d} phase={'decep' if deception_phase else 'nodec'} guided={guided} "
          f"compromised={hit} alerts={len(st.get('alerts',[]))} calls={u['calls']} ${u['cost']:.3f}", flush=True)
    if not hit:
        rec["held"] = False
        results.append(rec); return rec
    if force_rak:
        choice = {"choices": ["rak"], "rationale": "forced rak arm"}
    else:
        choice = A.purple_choose(st.get("alerts", []), summarize(tr), model=MODEL)
    env, dec = env_for(choice["choices"], deception_phase)
    print(f"    purple={choice['choices']} rationale={choice.get('rationale','')[:80]}", flush=True)
    reset_foothold()
    H.start(deception=dec, app_env=env)
    tr2, u2 = A.red_run(model=MODEL, max_steps=STEPS, guided=guided)
    st2 = H.app_state(); hit2 = H.compromised(st2)
    rec.update({"purple": choice, "applied": env, "reattack_compromised": hit2,
                "held": not hit2, "reattack_cmds": [t["cmd"] for t in tr2 if t.get("cmd")],
                "reattack_alerts": len(st2.get("alerts", [])), "usage2": u2})
    print(f"    re-attack compromised={hit2} -> {'HELD' if not hit2 else 'NOT HELD'}", flush=True)
    results.append(rec); return rec


def main():
    args = sys.argv[1:]
    guided = "--guided" in args
    deception = "--deception" in args
    force_rak = "--force-rak" in args
    n = int(next((a for a in args if a.isdigit()), "2"))
    H.build()
    print(f"== live rerun: model={MODEL} n={n} guided={guided} deception={deception} force_rak={force_rak} ==")
    results = []
    for i in range(1, n + 1):
        one_loop(i, guided, deception, force_rak, results)
    H.stop_all()
    out = os.path.join(H.BASE, "rerun-live.json")
    json.dump(results, open(out, "w"), indent=2)
    comp = sum(r["attack_compromised"] for r in results)
    held = sum(r.get("held", False) for r in results)
    cost = sum(r["usage"]["cost"] for r in results) + sum(r.get("usage2", {}).get("cost", 0) for r in results)
    print(f"\n== live summary: attack_compromised={comp}/{len(results)}  reattack_held={held}  cost=${cost:.4f} -> {out} ==")


if __name__ == "__main__":
    main()