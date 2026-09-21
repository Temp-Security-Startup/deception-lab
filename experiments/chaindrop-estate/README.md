# ChainDrop-style registry-worm estate

A second, independent lab estate built from the shape of the [ChainDrop npm worm](../../docs/incidents/INCIDENT-CATALOG.md#chaindrop-npm-worm)
(August 2026): a malicious package version runs from an npm `preinstall` hook, harvests the
publisher/CI credentials on the runner, and uses them to republish every package it can reach.
This estate asks what actually stops that, and what only appears to.

## The model

`registry.py` is a minimal npm-like registry. It runs in two roles:

- **real** (`DECOY=0`): accepts `@acme/*` publishes only with the real publish token.
- **maplepot** (`DECOY=1`): accepts canary tokens and records decoy publishes.

`worm.py` is a harmless stand-in for the install-time payload. It does three things, all
pointed at lab paths: read the runner's credential files (`npmrc`, AWS, kube, ssh), write the
loot to a directory, and republish `@acme/core@9.9.9-worm` with the harvested token. It is not
usable outside the lab.

`run_local.py` runs three arms and scores from registry ground truth, never from what the worm
claims.

## The three arms

| Arm | Runner credential on disk | Containment | Expected |
|---|---|---|---|
| **baseline** | real publish token | none | harvest, exfil, real republish |
| **rak** | real publish token | rak policy: exec allowlist, file deny on the credential dir, egress allowlist to the registry only | harvest and exfil kernel-denied; no token, no republish |
| **deception** | canary token | none | worm republishes, but the real registry routes a canary publish to the maplepot; real packages untouched; tripwire fires |

## Result: 13/13 (deterministic, no Docker, no model calls)

```
== RESULT: 13 passed, 0 failed ==
  ChainDrop-style estate verified: baseline lands, rak contains, deception diverts.
```

The rak arm is the interesting one. The install hook still runs (we do not patch anything), but it
is denied the credential file and the exfil directory, so it exits with no token:

```json
{"pkg": "@acme/leftpad", "read": [], "exfil": "ERR:PermissionError", "publish": "no", "token": null}
```

The deception arm shows the route-bound property working: the harvested canary token is
meaningless on the real registry, the publish lands in the decoy, and the canary use is a
tripwire:

```json
{"read": ["npmrc"], "exfil": "yes", "publish": "@acme/core@9.9.9-worm",
 "token": "CANARY-NPM-TOKEN-7f3a", "publish_tag": "maplepot"}
```

## Run

```sh
python3 run_local.py
```

Needs `cc` and Linux (Landlock for the rak arm). No Docker, no API key. Artifacts and logs land
in `/tmp/chaindrop-rerun/`.

## What this estate does not model

- Real npm; the tarball download and lifecycle resolution are stubbed.
- Real malware; `worm.py` is a few lines that touch only harness paths.
- The full republish fan-out; the pest propagates one package.
- Kernel BPF-LSM; the rak arm is Landlock enforcement of the rak policy shape, as in the
  [parser estate](../maple-rerun/README.md).