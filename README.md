# Deception & Containment Lab

We built this on top of someone else's experiment.

The [Maple Loop Experiment](https://github.com/Temp-Security-Startup/maple-loop-experiment) took a
real breach, rebuilt the attack chain in a small Docker lab, and let two LLM agents fight over it
in a loop. One attacks, one defends, then the same attacker comes back to see whether the fix
held. Their write-up is worth reading before this one, because the idea we care about is theirs.

The re-attack is the part I keep coming back to. Security work usually stops when the scanner
reports something or the pentester gets a shell, and neither of those tells you whether the fix
closes the path the attacker actually took. The only way to know is to keep the attacker and send
it back in after the fix.

So we took their loop and made the test harder. We added a containment arm from our own tooling,
closed a few holes we found in the lab, and built a second estate from a different incident. Then
we made the defender side an experiment too. We want to know which tools in our blue arsenal
actually stop the chain and which ones just look like they do.

None of this touches real software. The incidents are real, the bugs are toys we wrote, and there
are no real users or data anywhere in the repo.

## What the Maple Loop Experiment set out to prove

Their starting point was the Hacktron write-up on the OpenAI forum breach: a crafted image hit a
memory bug in an image decoder, that gave code execution on a low-trust forum, the forum shared an
identity plane with the high-trust app, and an employee's connected coding agent had write access
to an internal repo. They rebuilt that chain in miniature so the agents had something real to act
on.

The claim is that the loop is the artifact worth having, more than any single defense. Seccomp, a
virtual patch, and identity segmentation are all off-the-shelf. What they say does not exist as a
product is the closed loop: an attacker that finds a multi-stage path, a defender that picks a
mitigation from an arsenal, and a re-attack that measures whether the mitigation held.

They ran 40 loops and reported that the attack landed about 60% of the time without deception,
that every fix held on re-attack, and that deception diverted the attacker every time. They were
also flagged the last number themselves, which mattered to us. It held against a blind, curl-driven
agent, and their own earlier runs showed a capable agent spoofing the fingerprint and walking
around the decoy. Their conclusion was that against an adaptive adversary, deception slows the
attacker down and does not stop one.

That matches what we have seen, and it is where our work picks up.

## What we changed

A loop is only as good as its measurement, so most of our work went into the parts that produce
the number.

Their red agent was handed the exploit bytes and the API map in its system prompt. That makes for
a reliable demo and a misleading capability number. We added an unguided prompt and ran both. In
our rerun the guided agent compromised 2 of 2, and the unguided one got code execution and then
failed to find the rest of the chain. If you want to claim a discovery result, you have to withhold
the map.

Their attacker container was never reset between loops, so later runs inherited exploit scripts
from earlier ones. We wipe the foothold before every run.

Their edge decided a client was an automated attacker and diverted it, but that decision never
reached the defender agent. The loop could not use its own best signal. We wired it in.

Two bugs in their containment defeated the deception outright. The real app accepted any credential
beginning with the canary prefix, and the decoy shared a network and a real secret with the real
app. Either one lets an attacker who reaches the decoy mint a real change. We fixed both, and we
treat the second one as the real lesson: no decoy survives a shared credential.

We added a second estate from a different incident, and we put our own containment tool in the
arsenal.

## Testing the blue arsenal

This is the question we care about most. Which of our tools removes the attacker's ability, and
which one only removes one link while leaving the rest?

The parser estate ships six defenses and the loop applies them as arms. Here is what we measured,
scored from the estate's recorded state. What an agent claims does not move the number:

- A virtual patch fixes the decoder at the sink. The overflow is rejected, nothing else is needed.
- Seccomp lets the hijack land and kills the process at `execve`. One link, and a reliable one.
- Identity segmentation blocks the cross-tier redemption, so the stolen session cannot become an
  app identity. The RCE still happens.
- Gating the connected agent closes the pivot where a hijacked session drives an AI agent that
  holds CI write. The account takeover still happens.
- Deception detects and diverts. It does not stop a capable attacker, and the published run's
  perfect diversion number is a statement about a blind agent, not about the technique.
- Our rak containment is the one we were most curious about. It leaves the memory bug in place and
  denies the decoder the things it needs next: the session secret and the network. The hijack lands
  and is inert.

On re-attack, capability removal is what holds. In our live arm the guided attacker compromised
both runs without a defense, and both re-attacks failed once rak was on. The attacker did not give
up, it re-ran the exploit and kept trying to read the secret and reach the app, and it was denied
each time. That is the difference between a fix and a speed bump.

## The two estates

### Parser estate

The shape of the [OpenAI forum breach](docs/incidents/INCIDENT-CATALOG.md#openai-hacktron): image
RCE, a readable session secret, a cross-tier identity pivot, and a connected agent that can reach a
protected release path.

`experiments/maple-rerun/`. Report: `docs/incidents/MAPLE-RERUN-2026-09-21.md`.

All 20 deterministic checks pass without Docker and without spending a token. In the live arm the
unguided attacker compromised nothing in two runs, the guided attacker compromised both, and rak
held both on re-attack. The model was `deepseek/deepseek-v4.1-flash` through OpenRouter.

### Registry-worm estate

The shape of the [ChainDrop npm worm](docs/incidents/INCIDENT-CATALOG.md#chaindrop-npm-worm): a
package install hook harvests the runner's credentials and republishes packages with the stolen
token.

`experiments/chaindrop-estate/`.

13 of 13. Without a defense the hook reads the real token, writes its loot, and lands a poisoned
release. Under rak the hook still runs and is denied the credential file and the exfiltration
directory, so it has no token. With deception the runner holds a canary token instead, the worm
thinks it won, and the publish lands in the decoy while the canary use trips a tripwire.

## What we found

1. Deception buys detection and containment, not a wall. A decoy a capable attacker can read or
   spoof is friction, and its real value is the early signal plus the fact that the attacker is
   somewhere else.
2. A decoy only holds if it answers the whole objective. One fake flag when the task needs two gets
   pocketed, and the attacker speeds up.
3. Detection has to trigger a response. A passive decoy gets ignored while the real target is
   visible, and the test that matters is whether any attacker route can reach real data or mint a
   real credential. Not whether the attacker looked convinced.
4. Guided attackers measure the prompt. The published compromise rate reproduced in our rerun only
   when the exploit and the API map were supplied.
5. Capability removal is what makes a fix hold. Rak contained an RCE that still landed, and the
   attacker that won twice without a defense lost twice with it.
6. Authorization and boundary bugs beat deception. A shared credential or a shared network will
   sink a good decoy every time.
7. Canary precision is meaningless without a named legitimate population. A canary a real user can
   reach produces false positives, and a canary nobody can reach produces nothing. It has to be
   reachable on the sanctioned path and actionable only off it.
8. Evidence has to be committed. The published headline lives in generated docs while the raw loop
   files sit in `.gitignore`, so you cannot re-derive it. Every number here ships with the harness
   and the JSON behind it.

## How we test

Each estate rebuilds the shape of an incident and runs the same arms:

- no defense
- a patch
- seccomp
- identity segmentation
- agent gating
- a rak policy
- deception

Two rules keep the scoreboard straight. A compromise or a held fix is read from the estate's
recorded state, never from the agent's own claim. And a benign request has to come back quiet and
leave that state empty, so the alarms are not rigged to fire.

The published experiment needs Docker. Ours runs as localhost processes and uses Landlock for
isolation, which happens to enforce the same allowlist and deny shape a rak policy compiles. That
lets both estates run anywhere with a Linux kernel and a C compiler. The trade-offs are in each
report.

## Repository layout

```
README.md
docs/incidents/incidents.json                 the incident catalog, 19 entries
docs/incidents/INCIDENT-CATALOG.md            generated from the JSON
docs/incidents/MAPLE-RERUN-2026-09-21.md      parser-estate report
tools_gen_incidents.py
experiments/maple-rerun/                      parser estate
experiments/chaindrop-estate/                 registry-worm estate
```

## Run it

Deterministic arms, runnable with Python and a C compiler:

```sh
cd experiments/maple-rerun && python3 run_local.py       # 20 of 20
cd experiments/chaindrop-estate && python3 run_local.py  # 13 of 13
```

Live parser-estate loop, which spends a little money on OpenRouter:

```sh
cd experiments/maple-rerun
python3 run_loop_local.py 2                          # unguided attacker
python3 run_loop_local.py 2 --guided --force-rak     # guided attacker, rak re-attack
```

Rebuild the catalog after editing the JSON:

```sh
python3 tools_gen_incidents.py
```

## The incident catalog

The catalog collects 19 recent incidents that share the shapes we test: parser-RCE chains, registry
worms, agent prompt injection, OAuth identity chains, autonomous-agent intrusions, AI-introduced
vulnerabilities, and a backlog of initial-access primitives. Each entry has the chain, the role an
AI agent played, the deception and canary surface, a rak containment fit, and the estate stages it
maps to.

We picked ChainDrop for the second estate because a self-propagating credential harvester is the
hardest thing to fake your way out of. Klue and the OAuth chain are next, then the agent-pivot cases
(Deadbugz, Clinejection) and the newer libheif RCE in Next.js.

## What we do not claim

With small n and one attacker model per live arm, the live numbers are a rough capability signal.
The host harness uses Landlock where the published lab uses Docker network namespaces, and the
deterministic arms carry more weight than the live ones. The vulnerabilities are toy instances at
tutorial difficulty, so the exploit itself stays a toy. And the incidents are recent, so the
catalog is a snapshot with links to the sources.

## Credit

The loop and the question start with the
[Maple Loop Experiment](https://github.com/Temp-Security-Startup/maple-loop-experiment). We disagree
with a couple of their conclusions and we changed their harness, but the framing is theirs.

MIT, see [LICENSE](LICENSE).