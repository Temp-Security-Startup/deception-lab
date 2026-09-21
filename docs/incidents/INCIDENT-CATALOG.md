# Incident catalog: real breaches to test deception and containment against

_Updated 2026-09-21. Source of truth: `incidents.json`; this file is generated._

A curated, extensible list of real incidents whose shape can be reproduced as a lab estate and used to test the two Maplepot questions (is this an attacker? can we burn their time?) plus the prevention question (does the fix hold?). Each entry names the chain, the deception surface, a rak-agent containment fit, and how it maps onto the maple v2 estate stages V1..V10.

## How to use

- Pick an entry, reproduce only its SHAPE against a stand-in bug (never the real weaponized exploit), the way the maple-loop-experiment does for the OpenAI case.
- For each, define: sanctioned route (REAL) vs attacker route (decoy), the canary/credential that must be earned behind an exploit, and the containment invariant (no decoy can reach REAL or mint a REAL credential).
- Add the defense as an arm: no-defense / seccomp / vpatch / segmentation / agent_gating / rak-exec / rak-file / rak-egress / full-rak. Then re-attack and record whether the fix held.
- Score on: attacker compromise (from estate ground truth, never the agent claim), decoy belief, canary precision vs a named legitimate population, tokens burned, and whether any REAL data/credential leaked through the decoy path.
- A working arm ladder (no-defense / vpatch / seccomp / segmentation / agent_gating / rak) and a Docker-free harness already exist: see experiments/maple-rerun/ and docs/incidents/MAPLE-RERUN-2026-09-21.md.

## Legend

- **test_priority:** 1 = full multi-stage chain, reproduce now; 2 = adaptable, needs a small fixture change; 3 = single primitive / backlog.
- **ai_agent:** autonomous = the attacker or a major actor was an LLM agent; target = an LLM agent/bot was the victim/pivot; tool = AI coding tool introduced or amplified the bug; none = classic.
- **rak_fit:** How rak-agent's kernel policy (exec allowlist, inode-keyed file deny, egress allowlist) or its in-process operation guard would cut the link.

## Patterns

- `parser_rce_chain`: Untrusted media parsed by memory-unsafe native code gives code exec, which yields a credential, which becomes identity/pivot into a high-value sink.
- `registry_worm`: Compromised maintainer/CI identity publishes malicious package versions; lifecycle hooks execute; credentials are harvested and the worm self-propagates.
- `agent_injection`: An LLM agent (issue triager, CI autofix, IDE assistant, MCP client) treats attacker-controlled content as instructions and acts with its own privileges.
- `oauth_identity_chain`: A third-party integration's OAuth token or legacy credential is stolen and replayed to reach customer data in an adjacent SaaS.
- `autonomous_agent`: An agent operates without a human in the loop, discovers and exploits a target, and exfiltrates credentials at machine speed.
- `ai_autofix`: An AI coding assistant authored or approved a change that introduced the vulnerability, and scanners missed it.
- `edge_primitives`: Internet-facing / control-plane auth bypass and RCE primitives (KEV) that supply initial access for any of the chains above.

## Catalog at a glance

| id | date | category | priority | one line |
|---|---|---|---|---|
| [`clinejection`](#clinejection) | 2026-02 | agent_injection | P1 now | A GitHub Issue title prompt-injected Cline's AI issue triager, which poisoned the GitHub Actions cache, pivoted to the nightly publish workflows, and stole VSCE_PAT/OVSX_PAT/NPM_RELEASE_TOKEN; a third party then published a malicious Cline CLI with a postinstall openclaw. |
| [`tanstack-teampcp`](#tanstack-teampcp) | 2026-05 | registry_worm | P1 now | TeamPCP backdoored 42 TanStack packages with the Shai-Hulud credential harvester; harvested tokens were later used to download ~170 of CrowdSec's private GitHub repositories. |
| [`klue-oauth-icarus`](#klue-oauth-icarus) | 2026-06 | oauth_identity_chain | P1 now | Attackers used a compromised legacy credential in Klue's integration infrastructure to mint OAuth tokens and query customer Salesforce environments at scale, then extorted victims. |
| [`huggingface-agent-breach`](#huggingface-agent-breach) | 2026-07 | autonomous_agent | P1 now | An autonomous agent operating without attacker-side guardrails breached Hugging Face, stole cloud and cluster credentials, and moved laterally across internal clusters. |
| [`openai-hacktron`](#openai-hacktron) | 2026-07 | parser_rce_chain | P1 now | An unpatched, no-CVE libheif heap overflow on Discourse, chained with an SSO misconfiguration, let attackers silently take over employees' ChatGPT/Codex accounts and instruct a connected Codex to open PR #1186742 in OpenAI's internal monorepo. |
| [`chaindrop-npm-worm`](#chaindrop-npm-worm) | 2026-08 | registry_worm | P1 now | A Mini Shai-Hulud variant runs from npm preinstall, harvests npm/GitHub/AWS/Kubernetes/Vault credentials, republishes every package the stolen identity can reach, and injects Claude/VS Code configs for developer-to-developer spread. |
| [`nextjs-libheif-avif`](#nextjs-libheif-avif) | 2026-08 | parser_rce_chain | P1 now | Next.js passes attacker AVIF through sharp -> libheif; nested identity-derivation and auxiliary item references build two Alpha planes at different bit depths and trigger a heap overflow (GHSA-2xp9-vwfh-vxw4, CVSS 9.5); patches disable AVIF until upstream is fixed. |
| [`deadbugz-mcp`](#deadbugz-mcp) | 2026-09 | agent_injection | P1 now | A malicious MCP server answers benignly until a per-client call counter hits three, then rewrites its tool descriptions to instruct the agent to collect SSH keys, AWS credentials, shell history, and Kubernetes config, and to conceal it; delivered via a PR that edits the repo's MCP config. |
| [`salesloft-drift`](#salesloft-drift) | 2025-08 | oauth_identity_chain | P2 next | Attackers stole Drift integration OAuth tokens and used them to query Salesforce instances of many downstream customers, exfiltrating CRM data. |
| [`axios-npm`](#axios-npm) | 2026-03 | registry_worm | P2 next | The axios maintainer account was compromised (email swapped), a malicious dependency used a postinstall hook to run an obfuscated dropper, and a WAVESHAPER-style RAT was installed on Windows and macOS. |
| [`storm2949-identity-cloud`](#storm2949-identity-cloud) | 2026-05 | oauth_identity_chain | P2 next | Social engineering plus SSPR/MFA-prompt abuse took over an Entra ID identity; the actor then used legitimate cloud management features to reach M365 data, Azure control/data planes, Key Vaults, storage, and remote code exec on VMs. |
| [`snowflake-copilot-autofix`](#snowflake-copilot-autofix) | 2026-06 | ai_autofix | P2 next | A merged PR replaced a safe jq/env pattern with direct ${{ github.event.issue.title }} interpolation in jira_issue.yml; an unauthenticated issue title then executed commands in a GitHub Actions runner and exfiltrated a Jira token. |
| [`gitlost-github-agentic`](#gitlost-github-agentic) | 2026-07 | agent_injection | P2 next | An unauthenticated attacker opens an issue on a public repo; the org's agentic workflow reads it and, because the agent has read access to private repos too, posts private README contents in a public comment. |
| [`llmstxt-pandex`](#llmstxt-pandex) | 2026-09 | agent_injection | P2 next | Manipulated llms.txt guidance files caused agents at named Fortune-500 companies to fetch and run attacker packages across npm, PyPI, RubyGems, NuGet, crates.io, and Packagist, with no prompt injection and no social engineering. |
| [`openai-rogue-agents-expansion`](#openai-rogue-agents-expansion) | 2026-09 | autonomous_agent | P2 next | Follow-on reporting that OpenAI's autonomous agents used additional sites and conducted unauthorized communications beyond the initially disclosed incident. |
| [`vscode-token-theft`](#vscode-token-theft) | 2026-06 | oauth_identity_chain | P3 backlog | A VS Code vulnerability allowed a one-click theft of the user's GitHub token, turning an IDE interaction into repository access. |
| [`asyncapi-npm`](#asyncapi-npm) | 2026-07 | registry_worm | P3 backlog | Malicious AsyncAPI package versions delivered their payload at import time rather than install time, evading defenses that only watch lifecycle scripts. |
| [`coder-supply-chain`](#coder-supply-chain) | 2026-09 | registry_worm | P3 backlog | An advisory for the Coder project covering a supply-chain attack that served malicious packages to users. |
| [`edge-auth-primitives-2026`](#edge-auth-primitives-2026) | 2026-09 | edge_primitives | P3 backlog | Recent KEV additions that supply initial access for a chain: edge/appliance auth bypass and RCE, plus AI-gateway and registry auth flaws. |

## Parser Rce Chain

> Untrusted media parsed by memory-unsafe native code gives code exec, which yields a credential, which becomes identity/pivot into a high-value sink.

### `openai-hacktron` - OpenAI forum: libheif heap overflow -> SSO account takeover -> connected Codex -> internal monorepo PR

**Date:** 2026-07 · **Actor:** Hacktron research (Harsh Jaiswal, Mohan Pedhapati, Rahul Maini) · **Pattern:** `parser_rce_chain` · **AI-agent role:** `target` · **Test priority:** P1 now · **Status:** reproduced in maple-loop-experiment

An unpatched, no-CVE libheif heap overflow on Discourse, chained with an SSO misconfiguration, let attackers silently take over employees' ChatGPT/Codex accounts and instruct a connected Codex to open PR #1186742 in OpenAI's internal monorepo.

Sources: [primary source](https://www.hacktron.ai/blog/hacking-openai)

**Chain**
- **initial access:** Crafted HEIC/HEIF upload; Discourse -> ImageMagick -> libheif heap buffer overflow (no CVE, Debian backport missing).
- **identity:** Forum shared the 'Sign in with OpenAI' identity plane; forum compromise redeemed for ChatGPT/Codex account access with no password.
- **pivot:** Victim employee's connected Codex agent held GitHub org write; instructing it acted with the agent's own authority.
- **impact:** PR #1186742 in openai/openai internal monorepo; potential reach to Slack/email connectors.

**Deception / canary opportunities**
- Route-bound decoy media-processing service so an exploit request terminates with false success and canary secrets.
- Canary forum-session credential readable only off the sanctioned route (E5c/E11 shape).
- Decoy connected-agent endpoint wired to a fake registry so a hijacked session 'publishes' into nothing and trips a tripwire.

**rak-agent containment fit**
- Decode worker: exec allowlist (only the decoder), inode-keyed deny on the session-secret file, egress off -> the RCE cannot read the secret or call the IdP.
- Bootstrap/interpreter guard so a Python handler cannot shell out to a second interpreter with attacker args.

**Other prevention:** vpatch (bounds check); seccomp (kill execve); SSO tier segmentation; connected-agent gating on non-interactive sessions; registry publish requires CI identity

**Maps to estate stages:** V1, V2, V3, V8, V4, V5, V6, V10

**Notes:** The anchor case. Its two weak points in the existing reproduction: the red agent is handed the chain, and the decoy can reach the real app on the shared network while accepting any APP-CANARY token.

### `nextjs-libheif-avif` - Next.js AVIF optimization: libheif heap overflow -> unauthenticated RCE

**Date:** 2026-08 · **Actor:** disclosed by Hacktron (rootxharsh); coordinated by KarimPwnz · **Pattern:** `parser_rce_chain` · **AI-agent role:** `tool` · **Test priority:** P1 now · **Status:** candidate

Next.js passes attacker AVIF through sharp -> libheif; nested identity-derivation and auxiliary item references build two Alpha planes at different bit depths and trigger a heap overflow (GHSA-2xp9-vwfh-vxw4, CVSS 9.5); patches disable AVIF until upstream is fixed.

Sources: [primary source](https://thehackernews.com/2026/08/nextjs-patches-critical-avif-and.html)

**Chain**
- **initial access:** POST an attacker-controlled AVIF to any Next.js image optimizer with image/avif enabled.
- **identity:** RCE as the Node/image worker; process env and mounted secrets in reach.
- **pivot:** From the worker, reach adjacent services / cloud identity via metadata or mounted config.
- **impact:** Remote code execution pre-auth on a very common web framework.

**Deception / canary opportunities**
- Route-bound decoy image optimizer that always 'succeeds' with canary output; unauthenticated transform endpoints are pure attacker routes.
- Canary credential in the image worker's mount so a post-RCE read is a 100%-precision tripwire.

**rak-agent containment fit**
- Image worker is the textbook rak target: exec allowlist, deny the secret/config files by inode, egress allowlist to only the image store.
- Would contain the post-exploit stage even when the upstream library is still vulnerable.

**Other prevention:** libheif backport / disable AVIF; sandboxed decoder with no network; run in a seccomp profile

**Maps to estate stages:** V1, V2, V8

**Notes:** Cleanest modern instance of the exact V1 shape; libheif is the same library as the OpenAI case, so the stand-in decoder maps almost 1:1.

## Registry Worm

> Compromised maintainer/CI identity publishes malicious package versions; lifecycle hooks execute; credentials are harvested and the worm self-propagates.

### `tanstack-teampcp` - TanStack npm compromise (TeamPCP / Mini Shai-Hulud) -> 170 private CrowdSec repos exfiltrated

**Date:** 2026-05 · **Actor:** TeamPCP / UNC6780, and downstream Icarus · **Pattern:** `registry_worm` · **AI-agent role:** `tool` · **Test priority:** P1 now · **Status:** candidate

TeamPCP backdoored 42 TanStack packages with the Shai-Hulud credential harvester; harvested tokens were later used to download ~170 of CrowdSec's private GitHub repositories.

Sources: [primary source](https://www.crowdsec.net/blog/tanstack-supply-chain-attack-analysis)

**Chain**
- **initial access:** Compromise of a widely used npm publisher; malicious package versions published.
- **identity:** Malware harvests npm/GitHub/cloud credentials from installers and CI.
- **pivot:** Stolen GitHub token used to read private repositories of downstream users.
- **impact:** Private source code exposure across many downstream orgs, plus a data-extortion tail.

**Deception / canary opportunities**
- Decoy npm registry / decoy private repo with canary repos and a honey publish token; any clone of the canary private repo is a high-confidence signal.
- Tripwire on republish: a package version with no matching source commit/tag (TanStack's own tell) should alert, and can be served from a decoy registry to waste the attacker.

**rak-agent containment fit**
- On the CI runner and developer workstation, deny reads of ~/.npmrc, ~/.aws, ~/.kube, SSH keys by inode, allow egress only to the registry, and allow exec only for the package manager.

**Other prevention:** provenance/attestation and tag-to-commit binding; lockfile integrity + no lifecycle scripts; scoped short-lived publish tokens

**Maps to estate stages:** V3, V6, V9

**Notes:** Turns the estate objective from 'poison a package' into 'steal the private repo', which is a stronger diversion target and pairs well with a decoy private monorepo.

### `chaindrop-npm-worm` - ChainDrop: self-propagating npm worm across 400+ packages

**Date:** 2026-08 · **Actor:** unattributed · **Pattern:** `registry_worm` · **AI-agent role:** `tool` · **Test priority:** P1 now · **Status:** candidate

A Mini Shai-Hulud variant runs from npm preinstall, harvests npm/GitHub/AWS/Kubernetes/Vault credentials, republishes every package the stolen identity can reach, and injects Claude/VS Code configs for developer-to-developer spread.

Sources: [primary source](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)

**Chain**
- **initial access:** preinstall lifecycle script in a malicious package version (no source commit/tag behind it).
- **identity:** Harvests npm, GitHub, AWS, Kubernetes, and HashiCorp Vault credentials; uses OIDC publishing permissions in CI.
- **pivot:** Republishes modified tarballs with the stolen npm token; plants AI-assistant config files to spread between developers.
- **impact:** 400+ packages poisoned; encrypted exfil via HTTPS with GitHub repos as fallback.

**Deception / canary opportunities**
- Decoy secret store (Vault) and canary AWS keys; reads are the detection. A decoy package registry can accept the republish and burn the worm's budget.
- Poisoned Claude/VS Code config is itself a deception surface: a decoy config that points at canary endpoints.

**rak-agent containment fit**
- Strongest fit in the catalog. Lifecycle script child processes are exactly the 'untrusted subprocess' rak contains: exec allowlist, deny credential files by inode, egress off/allowlist.
- Even after the package is installed, the credential harvest and republish cannot happen.

**Other prevention:** --ignore-scripts; OIDC-scoped publish with provenance; secret scanning + rotation; egress filtering on build runners

**Maps to estate stages:** V3, V6, V7, V9

**Notes:** Gives the loop a multi-step, self-propagating attacker whose objective is credential harvest + republish; ideal for testing whether a decoy registry holds it for the full budget (E6/E12 shape).

### `axios-npm` - Axios npm compromise: postinstall dropper -> cross-platform RAT

**Date:** 2026-03 · **Actor:** North Korea-nexus (per Google GTIG) · **Pattern:** `registry_worm` · **AI-agent role:** `none` · **Test priority:** P2 next · **Status:** candidate

The axios maintainer account was compromised (email swapped), a malicious dependency used a postinstall hook to run an obfuscated dropper, and a WAVESHAPER-style RAT was installed on Windows and macOS.

Sources: [primary source](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package/)

**Chain**
- **initial access:** Compromised maintainer account; malicious dependency added.
- **identity:** npm publish access; install-time execution on developer machines.
- **pivot:** Dropper self-deletes and reverts package.json to hide forensics; C2 beacon.
- **impact:** Cross-platform RAT on developers and CI.

**Deception / canary opportunities**
- Decoy npm account/registry with honey publish token; malicious version accepted into a decoy registry and its C2 sinkhole.
- Canary developer credentials in the install environment.

**rak-agent containment fit**
- postinstall child: exec allowlist, egress allowlist to the registry only, file deny on ~/.npmrc and cloud creds.

**Other prevention:** 2FA/hardware keys on publishers; provenance; --ignore-scripts

**Maps to estate stages:** V3, V6, V7

**Notes:** Concrete, well-documented lifecycle-hook case; good for calibrating rak's npm containment arm.

### `asyncapi-npm` - AsyncAPI npm compromise: import-time payload delivery

**Date:** 2026-07 · **Actor:** unattributed · **Pattern:** `registry_worm` · **AI-agent role:** `none` · **Test priority:** P3 backlog · **Status:** backlog

Malicious AsyncAPI package versions delivered their payload at import time rather than install time, evading defenses that only watch lifecycle scripts.

Sources: [primary source](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-the-asyncapi-npm-supply-chain-compromise/)

**Chain**
- **initial access:** Compromised package published.
- **identity:** Payload runs in any process that imports the library.
- **pivot:** Import-time execution in developer and CI processes.
- **impact:** Credential theft and remote access.

**Deception / canary opportunities**
- Decoy registry that intercepts the import-time fetch and serves canary payloads.

**rak-agent containment fit**
- The importing process is contained regardless of when the payload runs: exec allowlist + egress allowlist + file deny.

**Other prevention:** provenance / lockfile pinning; egress filtering

**Maps to estate stages:** V3, V6

**Notes:** Included because it defeats the common 'only scan install scripts' assumption, which is a good hostile test for a containment claim.

### `coder-supply-chain` - Coder supply-chain attack serving malicious packages

**Date:** 2026-09 · **Actor:** unattributed · **Pattern:** `registry_worm` · **AI-agent role:** `none` · **Test priority:** P3 backlog · **Status:** backlog

An advisory for the Coder project covering a supply-chain attack that served malicious packages to users.

Sources: [primary source](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65)

**Chain**
- **initial access:** Compromised distribution channel.
- **identity:** Install-time execution.
- **pivot:** Payload in the developer/CI environment.
- **impact:** Compromise of downstream installs.

**Deception / canary opportunities**
- Decoy distribution channel with canary artifacts.

**rak-agent containment fit**
- Same lifecycle/process containment as the other registry worms.

**Other prevention:** provenance; artifact signing

**Maps to estate stages:** V3, V6

**Notes:** Thin public detail so far; keep for completeness and revisit when the write-up matures.

## Agent Injection

> An LLM agent (issue triager, CI autofix, IDE assistant, MCP client) treats attacker-controlled content as instructions and acts with its own privileges.

### `clinejection` - Clinejection: prompt-injecting an AI issue triager to poison a release

**Date:** 2026-02 · **Actor:** Adnan Khan (researcher); a separate actor used the PoC · **Pattern:** `agent_injection` · **AI-agent role:** `autonomous` · **Test priority:** P1 now · **Status:** candidate

A GitHub Issue title prompt-injected Cline's AI issue triager, which poisoned the GitHub Actions cache, pivoted to the nightly publish workflows, and stole VSCE_PAT/OVSX_PAT/NPM_RELEASE_TOKEN; a third party then published a malicious Cline CLI with a postinstall openclaw.

Sources: [primary source](https://adnanthekhan.com/posts/clinejection/)

**Chain**
- **initial access:** Open a crafted GitHub issue on a public repo; the AI triager treats the title/body as instructions.
- **identity:** The triage workflow runs with broad privileges and has cache access shared with publish workflows.
- **pivot:** Actions cache poisoning pivots from triage to the Publish Nightly/NPM workflows.
- **impact:** Production-equivalent release credentials stolen; malicious CLI published to npm and the VS Code/OpenVSX marketplaces.

**Deception / canary opportunities**
- A decoy issue/PR with an embedded canary instruction; if the agent acts on it, that is the detection.
- Decoy publish workflow with honey release tokens so a hijacked cache path burns budget and trips a tripwire.

**rak-agent containment fit**
- Constrain the triager's process: no network except the forge API, file deny on runner credentials, exec allowlist; the cache-poisoning pivot cannot read publish secrets.

**Other prevention:** separate caches per workflow; least-privilege triage token; no long-lived PATs; human gate on publish

**Maps to estate stages:** V5, V6, V7

**Notes:** The best pure 'connected agent is the pivot' case besides OpenAI; the triager is a real LLM agent with real publish access, so the confused-deputy model is literal rather than abstracted.

### `deadbugz-mcp` - Deadbugz: malicious MCP server that turns on the agent after three calls

**Date:** 2026-09 · **Actor:** Pillar (per write-up) · **Pattern:** `agent_injection` · **AI-agent role:** `target` · **Test priority:** P1 now · **Status:** candidate

A malicious MCP server answers benignly until a per-client call counter hits three, then rewrites its tool descriptions to instruct the agent to collect SSH keys, AWS credentials, shell history, and Kubernetes config, and to conceal it; delivered via a PR that edits the repo's MCP config.

Sources: [primary source](https://omnafy.com/blog/deadbugz-malicious-mcp-server/)

**Chain**
- **initial access:** A pull request that adds/changes an MCP server entry in a shared config file.
- **identity:** The agent runs with the developer's ambient credentials and filesystem access.
- **pivot:** Tool descriptions (invisible to the human) become the instruction channel; delayed activation defers detection.
- **impact:** Credential collection from the developer environment, hidden from the operator.

**Deception / canary opportunities**
- Decoy MCP server with canary credentials and canary tool descriptions; acting on them is a high-confidence detection.
- Route-bound decoy for any MCP server not on the sanctioned list.

**rak-agent containment fit**
- Constrain the MCP server AND the agent process: file deny on SSH/AWS/K8s config by inode, egress allowlist, exec allowlist. This stops the collection even when the tool description is poisoned.

**Other prevention:** allowlist MCP servers; review config changes; show tool descriptions to humans; no ambient creds to agents

**Maps to estate stages:** V5, V7

**Notes:** Best test of the deception-vs-containment split: the poisoned instruction is invisible to the human, so only process/egress containment reliably stops it.

### `gitlost-github-agentic` - GitLost: indirect prompt injection leaks private repos through a GitHub agentic workflow

**Date:** 2026-07 · **Actor:** Noma Labs · **Pattern:** `agent_injection` · **AI-agent role:** `autonomous` · **Test priority:** P2 next · **Status:** candidate

An unauthenticated attacker opens an issue on a public repo; the org's agentic workflow reads it and, because the agent has read access to private repos too, posts private README contents in a public comment.

Sources: [primary source](https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/)

**Chain**
- **initial access:** Public GitHub issue containing a plausible-looking instruction (indirect prompt injection).
- **identity:** The agentic workflow's token spans public and private repos.
- **pivot:** Agent fetches private files and writes them back to a public comment.
- **impact:** Private repo content disclosure to an unauthenticated attacker.

**Deception / canary opportunities**
- Decoy private repo with canary content; any read and external write is an unambiguous detection.
- Decoy issue with canary instructions to measure injection susceptibility without exposing real data.

**rak-agent containment fit**
- Egress allowlist for the agent (forge API only) and file deny on other tenants/repos; the agent cannot exfiltrate even if injected.

**Other prevention:** split public/private agent tokens; content provenance / instruction-data separation; human review before posting

**Maps to estate stages:** V5, V9, V10

**Notes:** The cleanest demonstration that 'the context window is the attack surface'; ideal for a route-bound decoy that serves private-looking canary data on any unauthenticated agent route.

### `llmstxt-pandex` - Fortune-500 AI agents tricked via llms.txt into running attacker code

**Date:** 2026-09 · **Actor:** Pandex (Alon Hertz) · **Pattern:** `agent_injection` · **AI-agent role:** `target` · **Test priority:** P2 next · **Status:** candidate

Manipulated llms.txt guidance files caused agents at named Fortune-500 companies to fetch and run attacker packages across npm, PyPI, RubyGems, NuGet, crates.io, and Packagist, with no prompt injection and no social engineering.

Sources: [primary source](https://www.tomshardware.com/tech-industry/artificial-intelligence/researchers-easily-trick-fortune-500-companies-ai-agents-into-running-arbitrary-code-supply-chain-attack-via-llms-txt-guidance-file-illustrates-how-data-has-become-code)

**Chain**
- **initial access:** Poisoned llms.txt / docs that agents treat as setup instructions.
- **identity:** Agent executes install commands with its own environment access.
- **pivot:** Cross-registry package install as the payload delivery.
- **impact:** Arbitrary code in the agent's environment, i.e. in the enterprise.

**Deception / canary opportunities**
- Decoy llms.txt / docs endpoint serving canary install instructions; following them is the detection.
- Route-bound decoy package registry so the install 'succeeds' against canary packages.

**rak-agent containment fit**
- Agent process containment: exec allowlist for package managers, egress allowlist, file deny on credentials.

**Other prevention:** treat docs as untrusted input; pin and verify packages; agent egress policy

**Maps to estate stages:** V2, V3, V6

**Notes:** Shows that 'data has become code' at enterprise scale; a good stress test for any claim that the agent can be trusted to distinguish instructions from content.

## Oauth Identity Chain

> A third-party integration's OAuth token or legacy credential is stolen and replayed to reach customer data in an adjacent SaaS.

### `klue-oauth-icarus` - Klue compromise -> stolen OAuth tokens -> Salesforce data theft across customers (LastPass, Huntress, ...)

**Date:** 2026-06 · **Actor:** Icarus (UNC6395-linked) · **Pattern:** `oauth_identity_chain` · **AI-agent role:** `none` · **Test priority:** P1 now · **Status:** candidate

Attackers used a compromised legacy credential in Klue's integration infrastructure to mint OAuth tokens and query customer Salesforce environments at scale, then extorted victims.

Sources: [primary source](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)

**Chain**
- **initial access:** Compromise of a legacy integration credential.
- **identity:** OAuth tokens associated with the integration inherited access to customers' Salesforce orgs.
- **pivot:** Python scripts queried the Salesforce API for extended periods and exfiltrated data.
- **impact:** Customer CRM data theft at multiple downstream companies, including LastPass and Huntress.

**Deception / canary opportunities**
- Decoy OAuth integration / honey refresh token; any exchange or API query with it is a high-precision tripwire.
- Decoy Salesforce object with canary records that a mass-query job will sweep up.

**rak-agent containment fit**
- The integration worker should not be able to read the OAuth client secret or reach arbitrary SaaS endpoints; rak file-deny + egress allowlist contains the post-compromise replay.

**Other prevention:** short-lived tokens + audience scoping; per-tenant OAuth isolation; anomaly detection on API volume

**Maps to estate stages:** V4, V7, V10

**Notes:** The identity-supply-chain analogue of the OpenAI case: one integration's credential becomes access to every customer. Maps cleanly to the SSO/token stage of the estate.

### `salesloft-drift` - Salesloft Drift OAuth token theft -> Salesforce data theft (Cloudflare et al.)

**Date:** 2025-08 · **Actor:** UNC6395 · **Pattern:** `oauth_identity_chain` · **AI-agent role:** `none` · **Test priority:** P2 next · **Status:** candidate

Attackers stole Drift integration OAuth tokens and used them to query Salesforce instances of many downstream customers, exfiltrating CRM data.

Sources: [primary source](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)

**Chain**
- **initial access:** Compromise of the Drift integration (third-party SaaS).
- **identity:** OAuth refresh tokens for customer Salesforce tenants.
- **pivot:** Automated API queries against many tenants.
- **impact:** Widespread customer data theft (Cloudflare and others disclosed).

**Deception / canary opportunities**
- Decoy integration tenant with canary Salesforce records; any token replay triggers a tripwire.
- Honey refresh token placed where a compromised integration worker would read it.

**rak-agent containment fit**
- Integration worker file-deny on the token store and egress allowlist to the single sanctioned tenant.

**Other prevention:** token audience/tenant scoping; rotation on integration compromise; API volume anomaly detection

**Maps to estate stages:** V4, V7, V10

**Notes:** Precursor to Klue; useful as a second instance of the same pattern to test whether deception generalizes rather than overfits one incident.

### `storm2949-identity-cloud` - Storm-2949: Entra ID identity compromise -> M365 + Azure control-plane -> Key Vault/storage -> VM code exec

**Date:** 2026-05 · **Actor:** Storm-2949 · **Pattern:** `oauth_identity_chain` · **AI-agent role:** `none` · **Test priority:** P2 next · **Status:** candidate

Social engineering plus SSPR/MFA-prompt abuse took over an Entra ID identity; the actor then used legitimate cloud management features to reach M365 data, Azure control/data planes, Key Vaults, storage, and remote code exec on VMs.

Sources: [primary source](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/)

**Chain**
- **initial access:** Help-desk-style social engineering; attacker initiates SSPR and coerces the victim to approve MFA prompts.
- **identity:** Password reset and removal of existing MFA methods; unrestricted account access.
- **pivot:** Abuse of legitimate Azure management features for lateral movement with few classic IOCs.
- **impact:** M365 and file-hosting exfiltration; Key Vault/storage access; remote code execution on Azure VMs.

**Deception / canary opportunities**
- Decoy cloud identity / honey service principal; any control-plane action by it is a high-precision signal.
- Canary Key Vault secret and storage account whose read is a tripwire; a decoy VM profile to absorb runaway automation.

**rak-agent containment fit**
- On VMs and build hosts, deny reads of managed-identity endpoints' responses by containing the process and its egress; egress allowlist prevents metadata-based credential minting.

**Other prevention:** phishing-resistant MFA / number matching; conditional access; PIM / just-in-time roles; monitor control-plane events

**Maps to estate stages:** V4, V7, V10

**Notes:** Expands the estate beyond web+registry into cloud control plane; a good second substrate once the v2 estate is stable.

### `vscode-token-theft` - VS Code one-click GitHub token theft

**Date:** 2026-06 · **Actor:** researchers (SecurityWeek report) · **Pattern:** `oauth_identity_chain` · **AI-agent role:** `tool` · **Test priority:** P3 backlog · **Status:** backlog

A VS Code vulnerability allowed a one-click theft of the user's GitHub token, turning an IDE interaction into repository access.

Sources: [primary source](https://www.securityweek.com/vs-code-vulnerability-allows-one-click-github-token-theft/)

**Chain**
- **initial access:** Malicious extension/workspace interaction in the IDE.
- **identity:** The user's OAuth GitHub token is exfiltrated.
- **pivot:** Token used against the user's repositories.
- **impact:** Repository read/write with the victim's identity.

**Deception / canary opportunities**
- Honey GitHub token in the IDE credential store; use is a tripwire.

**rak-agent containment fit**
- Contain the extension host / process: egress allowlist, file deny on the token store.

**Other prevention:** fine-grained PATs; extension allowlisting; token binding

**Maps to estate stages:** V4, V7

**Notes:** A client-side identity-theft primitive that fits as an initial-access arm rather than a full chain.

## Autonomous Agent

> An agent operates without a human in the loop, discovers and exploits a target, and exfiltrates credentials at machine speed.

### `huggingface-agent-breach` - Hugging Face: an autonomous AI agent breached internal systems and stole cloud/cluster credentials

**Date:** 2026-07 · **Actor:** unattributed (agent powered by some model) · **Pattern:** `autonomous_agent` · **AI-agent role:** `autonomous` · **Test priority:** P1 now · **Status:** candidate

An autonomous agent operating without attacker-side guardrails breached Hugging Face, stole cloud and cluster credentials, and moved laterally across internal clusters.

Sources: [primary source](https://www.bleepingcomputer.com/news/security/hugging-face-breach-autonomous-ai-agent-system-internal-datasets-credentials/)

**Chain**
- **initial access:** Agent-driven probing/exploitation of exposed services.
- **identity:** Harvested cloud and Kubernetes cluster credentials.
- **pivot:** Lateral movement across several internal clusters.
- **impact:** Internal datasets and credentials exposed; forensic response itself constrained by model guardrails.

**Deception / canary opportunities**
- Decoy internal cluster with canary credentials and datasets; the agent's high volume makes it a good absorption target (E12b).
- Canary cloud creds in reachable config so any mint/use is a tripwire.

**rak-agent containment fit**
- Contain the agent's own process tree: exec allowlist, egress allowlist, file deny on credential stores. This is rak's core 'attacker is a process' thesis applied to an LLM agent.

**Other prevention:** network segmentation; short-lived workload identity; egress monitoring/deny

**Maps to estate stages:** V1, V7, V9, V10

**Notes:** The strongest standalone argument for testing agents as processes rather than as text; pairs directly with rak and with the E12b absorption result.

### `openai-rogue-agents-expansion` - OpenAI: rogue agents used at least 10 more sites / unauthorized communications

**Date:** 2026-09 · **Actor:** OpenAI agents (per Reuters/Qz reporting) · **Pattern:** `autonomous_agent` · **AI-agent role:** `autonomous` · **Test priority:** P2 next · **Status:** candidate

Follow-on reporting that OpenAI's autonomous agents used additional sites and conducted unauthorized communications beyond the initially disclosed incident.

Sources: [primary source](https://www.reuters.com/world/openais-rogue-agents-used-least-10-more-sites-unauthorized-comms-researchers-say-2026-09-09/)

**Chain**
- **initial access:** Agent-driven actions across external services.
- **identity:** Agent-held credentials/connectors.
- **pivot:** Unauthorized external communication and resource use.
- **impact:** Scope larger than first disclosed; accountability questions.

**Deception / canary opportunities**
- Decoy external endpoints that log and absorb agent traffic (E12b absorption).
- Canary connectors whose use is a tripwire.

**rak-agent containment fit**
- Agent egress allowlist is the direct control: an agent can only talk to sanctioned services.

**Other prevention:** human-in-the-loop for external comms; connector scoping; audit trails

**Maps to estate stages:** V5, V10

**Notes:** Good for testing whether a decoy can absorb a never-terminating autonomous agent (ties to the intangible-objective result).

## Ai Autofix

> An AI coding assistant authored or approved a change that introduced the vulnerability, and scanners missed it.

### `snowflake-copilot-autofix` - Snowflake Jira compromise via a CI bug introduced in a Copilot-Autofix-assisted PR

**Date:** 2026-06 · **Actor:** Wiz Red Agent (discovery) · **Pattern:** `ai_autofix` · **AI-agent role:** `tool` · **Test priority:** P2 next · **Status:** candidate

A merged PR replaced a safe jq/env pattern with direct ${{ github.event.issue.title }} interpolation in jira_issue.yml; an unauthenticated issue title then executed commands in a GitHub Actions runner and exfiltrated a Jira token.

Sources: [primary source](https://www.wiz.io/blog/red-agent-snowflake-copilot-cicd-bug)

**Chain**
- **initial access:** Open a GitHub issue with a crafted title; the workflow interpolates it into a shell command.
- **identity:** The Actions runner's Jira token (qa@snowflake.net) was exfiltrated.
- **pivot:** Token granted read access across engineering, security-compliance, and bug-bounty Jira projects.
- **impact:** Unauthenticated CI runner command execution and internal Jira data access; live for 5 days.

**Deception / canary opportunities**
- A decoy Jira token whose use trips a tripwire; a decoy fork/branch where the injection 'works' but is monitored.
- Canary issue title that only an injected runner would fetch.

**rak-agent containment fit**
- The injected shell child is exactly what rak's in-process operation guard blocks: the workflow may run one approved operation, not an arbitrary shell; plus egress allowlist and file deny on the Jira token.

**Other prevention:** env: indirection + jq --arg; least-privilege workflow token; SAST that flags expression injection

**Maps to estate stages:** V6, V7

**Notes:** Important because the vulnerability was INTRODUCED by an AI fix and missed by a scanner: a loop that re-attacks is exactly what would catch the regression.

## Edge Primitives

> Internet-facing / control-plane auth bypass and RCE primitives (KEV) that supply initial access for any of the chains above.

### `edge-auth-primitives-2026` - Initial-access primitives from the 2026 KEV firehose

**Date:** 2026-09 · **Actor:** various · **Pattern:** `edge_primitives` · **AI-agent role:** `none` · **Test priority:** P3 backlog · **Status:** backlog

Recent KEV additions that supply initial access for a chain: edge/appliance auth bypass and RCE, plus AI-gateway and registry auth flaws.

Sources: [primary source](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

**Chain**
- **initial access:** See CVE list.
- **identity:** Whatever the compromised component holds.
- **pivot:** Component-dependent.
- **impact:** Varies; several are unauthenticated RCE or auth bypass.

**Deception / canary opportunities**
- Route-bound decoy for an exposed management interface; canary admin credentials.

**rak-agent containment fit**
- Contain the exploited service process with rak so post-auth-bypass actions cannot read secrets or egress.

**Other prevention:** patch/upgrade; network segmentation; MFA on management planes

**Maps to estate stages:** V10

| CVE | product | class | KEV added |
|---|---|---|---|
| `CVE-2026-19490` | Citrix NetScaler | auth bypass (alternate path/channel) | 2026-09-09 |
| `CVE-2025-25249` | Fortinet multiple products | heap buffer overflow | 2026-09-09 |
| `CVE-2026-20079` | Cisco Firewall Management Center / SCC | auth bypass (alternate path/channel) | 2026-09-09 |
| `CVE-2026-84869` | ConnectWise ScreenConnect | improper privilege management / missing authorization | 2026-09-11 |
| `CVE-2026-85706` | GitLab CE/EE | path traversal | 2026-09-11 |
| `CVE-2026-42016` | JFrog Artifactory | incorrect authorization | 2026-09-11 |
| `CVE-2026-42018` | JFrog Artifactory | improper authentication | 2026-09-11 |
| `CVE-2026-59822` | BerriAI LiteLLM | improper authentication | 2026-09-02 |
| `CVE-2026-49869` | Kestra OSS | OS command injection | 2026-09-02 |
| `CVE-2026-76460` | Cisco Identity Services Engine | incorrect use of privileged APIs | 2026-09-16 |
| `CVE-2026-76461` | Cisco Secure Email Gateway | SQL injection | 2026-09-14 |

**Notes:** A plug-in board: pick one as the initial-access arm for a synthetic chain, the way the estate already ships a stand-in decoder. LiteLLM and Artifactory are especially relevant because they sit in the AI-gateway and package-registry positions this experiment cares about.
