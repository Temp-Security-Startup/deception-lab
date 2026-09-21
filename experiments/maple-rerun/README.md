# Parser estate (maple-loop-experiment rerun)

A Docker-free rerun of the [maple-loop-experiment](https://github.com/Temp-Security-Startup/maple-loop-experiment)
v2 estate, built to test a **rak-agent containment** arm and to fix several flaws found in review.
Full write-up: [`../../docs/incidents/MAPLE-RERUN-2026-09-21.md`](../../docs/incidents/MAPLE-RERUN-2026-09-21.md).

## What the estate models

The shape of the OpenAI forum breach: a crafted image exploits a memory-unsafe decoder for code
execution as the service user, the service reads an employee session secret, the session redeems
cross-tier for the employee's app identity, and the employee's connected AI agent holds CI write
to a protected release path.

## Files

| file | role |
|---|---|
| `run_local.py` | launches app + maplepot + edge as localhost processes and runs the 20-check deterministic matrix |
| `agents_local.py` | OpenRouter Red/Purple agents; unguided red prompt by default |
| `run_loop_local.py` | live attack -> defend -> re-attack loop |
| `app/rakwrap.c` | Landlock shim that enforces a rak-agent-shaped policy on an untrusted child |
| `maple-rerun.patch` | the full diff against the published v2 tree |
| `rak-estate-policy.json` | the estate containment expressed as a policy compiled by rak-agent's own code |
| `live-unguided.json`, `live-guided-rak.json` | raw live-run output |

## Run

```sh
python3 run_local.py                              # 20/20, no Docker, no API key
python3 run_loop_local.py 2                       # unguided live attacker
python3 run_loop_local.py 2 --guided --force-rak  # guided attacker, rak re-attack
```

The rak arm needs Linux with Landlock (kernel 5.13+). The deterministic matrix needs `cc` and
libseccomp headers. Logs land in `/tmp/maple-rerun/`.

## Fixes carried in the patch

- Canary credentials are accepted only by the decoy (`estate_app.valid_token`), so a
  decoy-reached attacker can no longer mint a real supply-chain change.
- The edge divert decision is posted to the real app as `D6/edge-divert`, so Blue can use it.
- The attacker foothold is wiped between loops.
- App and decoy run under a container-like Landlock cage: own source, own secret, own port.

## Limits

Single attacker model, small n. The cage is Landlock, not Docker network namespaces. The rak arm is
Landlock enforcement of the rak policy shape; the policy itself is compiled by rak-agent's real
`rak_guard.compile_policy`.