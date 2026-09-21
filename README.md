# Deception & Containment Lab

Two small lab estates, each built from the *shape* of a real breach, used to test three
questions that point-in-time security tools cannot answer:

1. **Detection:** when an attacker touches a canary, can we tell it is an attacker?
2. **Diversion:** once we know, can we burn its time and tokens on a path that never reaches the
   real target?
3. **Prevention:** after we apply a fix, does it actually hold when the *same* attacker comes
   back?

Everything here is a purpose-built stand-in. No real software is exploited and no real users or
data exist. The incidents are real; the vulnerabilities are toys that share the real shape.

---

## What we are trying to do

Security controls are usually evaluated at a point in time: a scanner says "you have an RCE," a
pentest says "we got in." Neither tells you whether the *fix* closes the path an actual attacker
used, or whether the attacker simply walks around it. Answering that requires owning the attacker
and sending it back in after the fix. This lab exists to make that loop real and measurable.

The beliefs under test:

- **Deception is detection and containment, not a wall.** A decoy that a capable attacker can
  read, spoof, or route around is friction. Its durable value is the signal and the containment.
- **The decoy must be bound to the route, not to a behavior.** A decision like "is this client a
  bot?" is spoofable and has no precision in an estate full of legitimate automation. A route
  that no legitimate principal ever uses is an attacker signal for free.
- **Detection and diversion must be coupled.** A passive decoy is ignored by an attacker that can
  still see the real target. Once the canary fires, the real target has to go away, and the decoy
  becomes the only thing that still answers.
- **Containment that removes capability is what makes a fix hold.** Patching, seccomp, identity
  segmentation, and process containment (a rak-agent policy) do not depend on fooling anyone.
- **A guided attacker measures the prompt, not the attacker.** If the red agent is handed the
  exploit bytes and the API map, a high compromise rate says little about autonomous discovery.
- **Containment is an invariant, not a percentage.** No attacker route may reach REAL data or mint
  a REAL credential, and a benign control must stay benign. We test that, not the attacker's story.

---

## The estates

### 1. Parser estate: image RCE to connected-agent supply chain

Shape of the [OpenAI forum breach](docs/incidents/INCIDENT-CATALOG.md#openai-hacktron) (July
2026): a crafted image hits a memory-unsafe decoder for RCE as the service user, the service can
read an employee session secret, the session redeems cross-tier for that employee's app identity,
and the employee's connected AI agent holds CI write that reaches a protected release path.

Files: [`experiments/maple-rerun/`](experiments/maple-rerun/). Full report:
[`docs/incidents/MAPLE-RERUN-2026-09-21.md`](docs/incidents/MAPLE-RERUN-2026-09-21.md).

**Deterministic matrix: 20/20, no Docker, no model calls.**
The real hijack lands and produces D2 identity, D5 connected-agent, and D4 supply-chain alerts plus
a recorded core-package publish. vpatch rejects the overflow (rc=2). seccomp kills the hijack
(SIGSYS). A naive client is diverted to the maplepot and the divert is wired to Blue as
D6/edge-divert. Under the rak arm the hijack **still lands** (the bug is untouched) but the
decoder gets `Permission denied` on the secret and its egress is denied, so there is no account
takeover and no publish.

**Live loop** (`deepseek/deepseek-v4.1-flash` via OpenRouter, small n, deception off):

| Arm | n | attack compromised | re-attack held | cost |
|---|--:|--:|--:|--:|
| unguided red prompt (recon only) | 2 | 0 / 2 | n/a | $0.039 |
| guided red prompt (published) | 2 | 2 / 2 | **2 / 2 under rak** | $0.037 |

The unguided agent got RCE and then failed to find the SSO redeem, the connected-agent list, or
the publish path. Handed the prompt, it compromised both times. Capability removal held both times.

### 2. Registry-worm estate: install-time credential harvest and republish

Shape of the [ChainDrop npm worm](docs/incidents/INCIDENT-CATALOG.md#chaindrop-npm-worm) (August
2026): a malicious package version runs from a `preinstall` hook, harvests the runner's package and
cloud credentials, and republishes packages with the stolen token.

Files: [`experiments/chaindrop-estate/`](experiments/chaindrop-estate/).

**13/13.** Baseline: the hook harvests the real token, writes loot, and lands a real poisoned
release. rak: the hook still runs but is denied the credential file and the exfil directory, so it
has no token and nothing lands. Deception: the runner holds a canary token, the worm "succeeds,"
but the real registry routes a canary publish to the maplepot, the real packages are untouched, and
the canary use is a tripwire.

---

## How we test

- **Reproduce the shape, not the weapon.** Toy decoder, stand-in worm, mock SSO and registry. The
  mechanics we claim are real (a real buffer overflow and control-flow hijack, real seccomp, real
  Landlock enforcement) are labelled as such; everything else says it is a model.
- **Arm ladder.** Every estate runs the same defenses as selectable arms: no defense, virtual
  patch, seccomp, identity segmentation, connected-agent gating, a rak-agent containment policy,
  and deception.
- **Ground truth only.** "Compromised" and "held" are read from the estate's recorded state (a
  package was published, a protected merge exists). The agent can narrate anything; it does not
  move the scoreboard.
- **A benign control.** A legitimate request must produce zero alerts and zero compromise, so the
  measurement is not rigged to always fire.
- **A fresh attacker per run.** The foothold is reset between runs, because a long-lived attacker
  that keeps its earlier exploit scripts is not an independent trial.
- **No Docker required for the deterministic path.** The published experiment needs Docker; these
  harnesses run as localhost processes and enforce isolation with Landlock, which is exactly the
  exec-allowlist / file-deny / egress-deny shape a rak policy compiles. The limits of that
  substitution are stated in each report.

---

## Conclusions so far

1. **Deception's robust value is detection plus containment, not a wall.** In the parser estate a
   blind, curl-driven attacker was diverted 100% of the time, but that is a statement about that
   attacker. A capable agent that suspects the fingerprint can spoof the handshake, and in the
   published build an attacker who reached the decoy could read the real secret and mint a real
   credential against the real app.
2. **A decoy only holds if it satisfies the whole objective.** A partial decoy (one fake flag when
   the task needs two) gets banked and can speed up the real attack.
3. **Couple detection to a response, and make containment an invariant.** A passive decoy is
   ignored while the real target is visible. The test is "can any attacker route reach REAL or mint
   a REAL credential?", not "did the attacker look fooled?"
4. **Guided attackers overstate capability.** In our rerun the published 0.60 compromise shape
   reproduced only when the exploit bytes and the API map were supplied. Unguided, the same model
   got code execution and never completed the chain. Any autonomy claim should be measured with the
   map withheld.
5. **Capability removal is what makes a fix hold.** Under rak, the parser RCE landed and was inert
   (secret read and egress kernel-denied), and the guided attacker that compromised 2/2 without a
   defense failed 2/2 on re-attack. seccomp and vpatch behave the same way.
6. **Authorization and boundary bugs beat deception.** Two concrete examples in the published
   build: the real app accepted canary credentials, and the decoy shared a network and a real
   secret with the real app. Both are fixed here by scoping the canary to the decoy and by giving
   each role its own files and port. No amount of decoy quality survives a shared credential.
7. **Canary precision is undefined without a named legitimate population.** A canary that
   legitimate users can reach gives false positives; a canary nobody can reach gives no signal. It
   has to be actionable only off the sanctioned path, and it has to be gated behind an action that
   only an attacker takes.
8. **Evidence has to be committed.** The published 40-loop result lives in generated docs while the
   raw loop files are gitignored, so the headline cannot be re-derived. Every number here ships
   with the harness and the raw JSON that produced it.

---

## What we do not claim

- Small n and one attacker model per live arm. These are capability signals, not rates.
- The host harness uses Landlock for isolation, not Docker network namespaces. The deterministic
  arms are the strong evidence; the live arms are directional.
- The vulnerabilities are toy instances at tutorial difficulty. We reproduce the chain, not the
  weapon.
- The incidents are recent and moving. The catalog records the shape we built from and links the
  primary sources.

---

## Repository layout

```
README.md                              this file
docs/incidents/incidents.json          incident catalog, source of truth (19 incidents)
docs/incidents/INCIDENT-CATALOG.md     generated view
docs/incidents/MAPLE-RERUN-2026-09-21.md   parser-estate rerun report
tools_gen_incidents.py                 regenerates the catalog view
experiments/maple-rerun/               parser estate: harness, patch, raw results
experiments/chaindrop-estate/          registry-worm estate: harness, registry, stand-in worm
```

## Run

Deterministic arms, no Docker, no API keys:

```sh
# parser estate (shape of the OpenAI forum breach)
cd experiments/maple-rerun && python3 run_local.py

# registry-worm estate (shape of ChainDrop)
cd experiments/chaindrop-estate && python3 run_local.py
```

Live parser-estate loop (uses OpenRouter, roughly $0.02 per loop):

```sh
cd experiments/maple-rerun
python3 run_loop_local.py 2                          # unguided attacker
python3 run_loop_local.py 2 --guided --force-rak     # guided attacker, rak re-attack
```

Regenerate the incident catalog after editing `incidents.json`:

```sh
python3 tools_gen_incidents.py
```

## The incident catalog

[`docs/incidents/INCIDENT-CATALOG.md`](docs/incidents/INCIDENT-CATALOG.md) holds 19 recent
incidents across seven patterns: parser-RCE chains, registry worms, agent prompt injection, OAuth
identity chains, autonomous-agent intrusions, AI-introduced vulnerabilities, and an initial-access
primitive backlog. Each entry names the chain, the AI-agent role, the deception and canary surface,
a rak containment fit, and how it maps onto the estate stages, so it can be turned into the next
estate.

Next up, in priority order: `chaindrop-npm-worm` (done here), `klue-oauth-icarus`,
`deadbugz-mcp`, `clinejection`, and `nextjs-libheif-avif`.

## License

MIT. See [LICENSE](LICENSE).