# Day-1 integration catalog

_Updated 2026-09-21. Source of truth: `integrations.json`; this file is generated._

The connectors and data feeds Maplepot needs so the loop we built in this repo can run against a real estate. The loop has to detect an attacker, divert it, remove its capability, and prove the fix held. Each entry says what data we get, what blue action it unlocks, how we demo it against one of our estates, and why it sits where it does in the order.

## How we ranked these

We rank a connection by how much of the attack chain it lets us cover, and by whether it can both detect and act. A feed that only alerts is worth less than one that also has a kill switch we can pull, and a feed that names the specific route or credential an attacker used is worth more than one that gives us a generic anomaly.

| criterion | question | why it matters |
|---|---|---|
| chain coverage | Which link does it cover: initial access, identity, code and CI, artifact, runtime, or the deception route? | A chain is only as useful as the links we can see and break. We already demonstrate a full chain in the parser estate, so the gaps are the integrations. |
| precision | Can it produce a signal that only an attacker generates? | Our detection thesis is that an attacker-only route or credential beats a behavioral score. We want feeds that can carry that kind of signal. |
| enforcement power | Can it remove the capability, or only report it? | The rerun showed capability removal is what makes a fix hold on re-attack. Alert-only integrations are supporting acts. |
| ground truth | Can we read the outcome to score a run? | A held verdict has to come from the estate's recorded state. The integration is often where that state lives. |
| access cost | Is there a read API and a webhook without an agent install? | Read-first gets us a demo in days, and keeps the change small. |
| blast radius | What breaks if our action is wrong? | Write actions on identity and CI can take down production. Those start in dry-run with a TTL and an audit trail. |


**Smallest day-one demo.** The smallest credible demo uses one attacker route through a proxy, one stolen identity at the IdP, one poisoned artifact at a registry, one canary secret in a vault, and one kernel denial at runtime. That combination lets us show the whole loop, detection to diversion to capability removal to a held re-attack, against the OpenAI and ChainDrop shapes we already run.

## At a glance

| id | tier | category | detect | act | ground truth | effort |
|---|---|---|---|:--:|:--:|---|
| [`artifact-registry`](#artifact-registry) | P0 day one | `artifact_supply_chain` | yes | yes | yes | low |
| [`code-cicd`](#code-cicd) | P0 day one | `code_pipeline` | yes | yes | yes | low |
| [`proxy-gateway`](#proxy-gateway) | P0 day one | `deception_route` | yes | yes | yes | medium |
| [`identity-idp`](#identity-idp) | P0 day one | `identity` | yes | yes | yes | medium |
| [`runtime-enforcement`](#runtime-enforcement) | P0 day one | `runtime_enforcement` | yes | yes | yes | high |
| [`secrets-vault`](#secrets-vault) | P0 day one | `secrets` | yes | yes | yes | low |
| [`agent-platform`](#agent-platform) | P1 first ninety days | `agent_platform` | yes | yes | yes | medium |
| [`cloud-control-plane`](#cloud-control-plane) | P1 first ninety days | `cloud_control_plane` | yes | yes | yes | medium |
| [`collaboration-canary`](#collaboration-canary) | P1 first ninety days | `collaboration` | yes | yes | yes | low |
| [`detection-response`](#detection-response) | P1 first ninety days | `detection_response` | yes | yes | yes | low |
| [`endpoint-edr`](#endpoint-edr) | P1 first ninety days | `runtime_enforcement` | yes | yes | yes | medium |
| [`asset-risk`](#asset-risk) | P2 later | `asset_risk` | no | no | yes | medium |
| [`threat-intel`](#threat-intel) | P2 later | `asset_risk` | no | no | yes | low |
| [`network-enforcement`](#network-enforcement) | P2 later | `deception_route` | yes | yes | yes | medium |
| [`identity-governance`](#identity-governance) | P2 later | `identity` | yes | yes | yes | medium |
| [`pam-bastion`](#pam-bastion) | P2 later | `identity` | yes | yes | yes | medium |

## The keys that make it hang together

Detection, containment, and verification only line up if the integrations agree on a set of identifiers. We ask every connector for these keys up front, even when it means mapping them ourselves, because a canary hit that cannot be tied to a session cannot trigger the right containment or prove the fix held.

| key | what it joins |
|---|---|
| `route_id / request_id / trace_id` | Bind a detection to the exact route that must be diverted or denied. |
| `session_id` | Tie a browser session to a canary touch and to a later containment action. |
| `principal (issuer + subject)` | Resolve a user across the IdP, code host, vault, and cloud. |
| `token_id / refresh_token_id / grant_id` | Revoke the exact credential an attacker replayed. |
| `agent_id / connector_id` | Gate a connected AI agent and revoke its connector separately from the user. |
| `workload_id / pid / process lineage` | Contain the process that read the canary or made the connection. |
| `package_id (name@version) / provenance digest` | Quarantine a release and prove the real registry stayed clean. |
| `secret_id / lease_id` | Revoke or rotate the credential that was read. |
| `canary_id` | Mark our planted credential, document, or hostname so any use is unambiguous. |
| `run_id / incident_id` | Attach every signal and action to one replay so the report is reproducible. |

## Guardrails for every connector

- Read-only first. Every connector starts with the smallest read scope, and write access is a separate grant we add only for a specific demo.
- Dry-run enforcement. Show what a control would do, on a copy, before it touches live traffic.
- Blast-radius query before action. Report how many workloads, users, or routes a selector would hit, and refuse above a threshold without a human.
- Reversible with a TTL. Every applied control carries an expiry and a one-call rollback.
- Full audit trail. The signal, the decision, the action, and the outcome are logged together and replayable.
- No credential retention. We read token metadata where the API allows it, and we never store the token itself.

## P0 day one

### `artifact-registry` - Package and artifact registry

**Tier:** P0 day one · **Category:** `artifact_supply_chain` · **Effort:** low · **Direction:** telemetry, enforcement, deception

**Examples:** npm, PyPI, JFrog Artifactory, GitHub Packages, OCI container registries, HashiCorp Nomad artifacts.

**Why here in the order.** This is the worm's goal and the easiest place to put a decoy that absorbs it. It gives us the publish event, the identity behind it, and the provenance, and it is where we can serve a canary registry that a harvest touches and the real one stays clean.

**Data we want**
- Events
  - publish
  - deprecate or yank
  - token use
  - download
  - provenance attestation
  - package diff
  - install lifecycle script
- Fields
  - name and version
  - publisher identity
  - token id
  - provenance or SLSA attestation
  - tarball hash
  - dependency changes
  - presence of preinstall or postinstall
  - source commit or tag
- APIs
  - npm audit and package webhooks
  - Artifactory webhooks and audit
  - PyPI
  - OCI registry notifications
  - Sigstore or SLSA attestations
- Join keys
  - package_id
  - token_id
  - principal
  - provenance digest

**Blue capability.** detection, diversion, prevention, verification.

**Actions it unlocks**
- quarantine a version
- revoke the publishing token
- block a publish without provenance
- serve a decoy registry for a canary token

**How we demo it**

Drawn from chaindrop-npm-worm and tanstack-teampcp. The install hook harvests a canary token. The publish goes to the decoy registry, and rak denies the credential read and the egress. What it proves: The real registry records no poisoned release, the decoy records the attempt, the canary use is a tripwire, and a benign CI publish still succeeds.

**Risks.** A decoy registry has to be trusted by the client, usually through DNS or a token scoped to the decoy; Yanking a package can break downstream builds.

**Fallback.** Read-only publish audit plus quarantine.

### `code-cicd` - Source control and CI/CD

**Tier:** P0 day one · **Category:** `code_pipeline` · **Effort:** low · **Direction:** telemetry, enforcement

**Examples:** GitHub and GitHub Actions, GitLab and GitLab CI, Jenkins, Argo CD, Buildkite, CircleCI.

**Why here in the order.** The supply-chain step and the connected-agent pivot both live here. It is the ground truth for whether a merge or a publish landed, and it is where an agent's action can be gated before it ships.

**Data we want**
- Events
  - pull request opened, reviewed, and merged
  - push
  - workflow run and job log
  - secret access
  - OIDC token exchange
  - package publish
  - branch protection change
  - app and personal token use
- Fields
  - actor
  - actor type (user, app, bot)
  - repository
  - ref
  - commit
  - workflow
  - job
  - runner id
  - OIDC claims
  - token id
  - trigger event
  - issue or PR title and body
  - package name and version
- APIs
  - GitHub webhooks, audit log, Actions API, OIDC
  - GitLab webhooks and audit events
  - Jenkins API
  - Argo events
- Join keys
  - principal
  - agent_id
  - token_id
  - workload_id
  - package_id
  - repo and commit

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- require a second reviewer for a protected path
- block a publish from a non-CI identity
- gate an agent action that came from a non-interactive session
- revoke an app or personal token

**How we demo it**

Drawn from clinejection, snowflake-copilot-autofix, openai-hacktron. Replay an attacker-controlled issue title into a workflow, then drive a connected agent to publish. Show the injection alert, the gated publish, and a re-attack that fails. What it proves: The attacker action is detected by actor type and trigger, the publish is refused without a CI identity, the agent pivot is gated, and the benign maintainer PR still merges.

**Risks.** Write access to repos or workflows is sensitive; Many events, so we need to filter to the ones that matter.

**Fallback.** Read-only audit log and webhooks, with enforcement left to existing branch protection.

### `proxy-gateway` - Reverse proxy, API gateway, service mesh, and DNS

**Tier:** P0 day one · **Category:** `deception_route` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** Envoy, Istio, NGINX, Traefik, Cloudflare, AWS ALB and Route 53, Cilium.

**Why here in the order.** This is the control point where route-bound deception is wired. A route that no legitimate principal uses gives us an attacker signal with no false positives, and the same box can send that route to the decoy. Without it, our best idea stays a lab fixture.

**Data we want**
- Events
  - request and response metadata
  - route match
  - client authentication outcome
  - mTLS or SPIFFE identity
  - upstream selected
  - authorization decision from ext_authz
  - DNS query and answer
- Fields
  - request id
  - trace id
  - host
  - path
  - method
  - route
  - client cert or SPIFFE id
  - session cookie
  - user-agent
  - TLS fingerprint
  - upstream cluster
  - decision
  - response code
- APIs
  - Envoy access log service and tap
  - Envoy ext_authz
  - Istio telemetry
  - NGINX and OpenResty access logs
  - Cloudflare Logpush
  - ALB access logs
  - Route 53 query logging
- Join keys
  - route_id
  - request_id
  - trace_id
  - session_id
  - client_cert
  - workload_id

**Blue capability.** detection, diversion, prevention, verification.

**Actions it unlocks**
- route the attacker route to a decoy
- taint the session so its later requests stay on the decoy
- deny egress from a tainted route
- block the request outright

**How we demo it**

Drawn from openai-hacktron, and the parser estate we already run. Wire a route that legitimate clients never take to the maplepot. Send a legitimate client down the sanctioned route and an attacker down the canary route. What it proves: The real target stays untouched and the decoy records the hit. The legitimate client is unaffected. We show the route decision, the decoy hit, and the empty real state in one report.

**Risks.** Inline blocking can break real traffic if the route map is wrong; TLS fingerprinting needs a termination point we control.

**Fallback.** Start in monitor mode and emit the would-be divert decision as an alert.

### `identity-idp` - Identity provider and OAuth or OIDC plane

**Tier:** P0 day one · **Category:** `identity` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak.

**Why here in the order.** Identity is the pivot in four of our catalog incidents, and it is where the kill switch lives. It gives us the cross-tier redemption signal, the token replay signal, and the ability to revoke the exact grant an attacker is using. Nothing else does both halves.

**Data we want**
- Events
  - sign-in
  - token grant
  - refresh token use
  - OAuth consent
  - MFA challenge
  - session start and end
  - cross-application access
  - admin role change
- Fields
  - timestamp
  - actor id
  - client or application id
  - grant type
  - scopes
  - audience
  - issuer
  - source IP
  - device id
  - session id
  - token id
  - refresh token id
  - result
  - risk score
- APIs
  - Okta System Log API and OAuth grants API
  - Entra sign-in and audit logs plus Microsoft Graph
  - Google Workspace Admin SDK Reports
  - standard OIDC and OAuth introspection
- Join keys
  - principal
  - session_id
  - token_id
  - issuer and audience
  - device_id

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- revoke a refresh token or the whole grant
- sign out the sessions for a user
- require step-up before a cross-tier redemption
- block cross-tier redemption at the policy layer

**How we demo it**

Drawn from klue-oauth-icarus and openai-hacktron. Replay a stolen refresh token from a new device. Serve the decoy integration so the token reaches canary records, then revoke the grant and turn on segmentation, and re-attack. What it proves: The cross-tier redemption fires as a high-precision detection, the decoy returns canary data, the revoke and segmentation void the replay, and the re-attack fails while a benign sign-in control still works.

**Risks.** Revoking the wrong grant logs out real users; Log schemas differ enough that the join keys need mapping.

**Fallback.** Read logs only and drive enforcement through the app's own IdP.

### `runtime-enforcement` - Runtime telemetry and kernel enforcement

**Tier:** P0 day one · **Category:** `runtime_enforcement` · **Effort:** high · **Direction:** telemetry, enforcement

**Examples:** CrowdStrike Falcon, Microsoft Defender, Sysdig, Tetragon, Auditd, rak-agent on BPF-LSM or Landlock.

**Why here in the order.** This is the last mile. Our rerun showed that capability removal is what makes a fix hold, and a policy on the process is the control that does it without patching the bug. It is also the feed that confirms a canary file was actually read.

**Data we want**
- Events
  - process exec
  - file open and read
  - network connect
  - process tree
  - container and workload identity
  - LSM denial
  - seccomp kill
- Fields
  - pid and tgid
  - parent pid
  - executable
  - argv
  - file path and inode
  - destination IP and port
  - container id
  - user
  - cgroup
  - policy decision
- APIs
  - CrowdStrike event streams
  - Defender advanced hunting
  - Sysdig and Tetragon eBPF
  - Auditd
  - LSM and seccomp hooks
- Join keys
  - workload_id
  - pid and lineage
  - canary_id
  - secret_id
  - route_id

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- deny a file read by inode
- deny an exec outside the allowlist
- deny egress to a destination
- kill the process

**How we demo it**

Drawn from openai-hacktron and nextjs-libheif-avif, via the parser estate. The decoder is hijacked and we want it contained. Apply the rak policy and re-run the exploit. What it proves: The hijack still lands, the secret read and the egress are denied in the kernel, the account takeover never happens, and the benign decode shows no denials.

**Risks.** Broad host access and a privileged sensor; A wrong policy can break a workload, so it needs a dry-run mode.

**Fallback.** Auditd or an unprivileged eBPF collector, with enforcement through rak's Landlock path.

### `secrets-vault` - Secrets manager and credential vault

**Tier:** P0 day one · **Category:** `secrets` · **Effort:** low · **Direction:** telemetry, enforcement, deception

**Examples:** HashiCorp Vault, AWS Secrets Manager, Google Secret Manager, Azure Key Vault, Kubernetes secrets.

**Why here in the order.** Canary credentials are the cheapest high-precision tripwire we have, and the vault is where we revoke the one an attacker stole. It closes the credential access link in the chain and gives us a clean detection with no false positives.

**Data we want**
- Events
  - secret read
  - lease issue, renew, revoke
  - dynamic credential creation
  - accessor identity
  - path enumeration
- Fields
  - secret path or id
  - principal
  - lease id
  - ttl
  - accessor
  - source IP
  - client
  - mount
- APIs
  - Vault audit devices and API
  - AWS Secrets Manager via CloudTrail
  - Kubernetes secrets audit
  - cloud secret manager audit logs
- Join keys
  - secret_id
  - lease_id
  - principal
  - workload_id

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- revoke a lease
- rotate or rewrap the secret
- plant a canary secret on the attacker route
- deny a read by inode at runtime

**How we demo it**

Drawn from chaindrop-npm-worm and openai-hacktron. Plant a canary secret where only an attacker would reach it. The worm or the RCE reads it, we revoke and rotate, and then re-attack. What it proves: The canary read is a detection, the decoy value is worthless, the revoke takes effect, and the re-attack cannot read the secret.

**Risks.** Rotation can break a running app; A canary secret has to look real enough to be worth reading.

**Fallback.** Static canary files watched by the runtime feed.

## P1 first ninety days

### `agent-platform` - AI agent gateway, MCP registry, and coding assistants

**Tier:** P1 first ninety days · **Category:** `agent_platform` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** LiteLLM, MCP servers and registries, GitHub Copilot, Cline, Cursor, internal agent frameworks.

**Why here in the order.** A connected agent is a new privileged principal, and several catalog incidents treat it as the pivot. We need the agent's identity and its tool calls, separate from the user's, to gate an action that came from a hijacked session.

**Data we want**
- Events
  - tool call
  - tool description or schema fetched
  - agent session start
  - connector grant
  - prompt and completion metadata
  - egress destination
- Fields
  - agent id
  - connector id
  - user behind the agent
  - session interactivity
  - tool name and arguments
  - server or model
  - egress host
  - scope or grant
- APIs
  - LiteLLM proxy logs
  - MCP server registry and tool listing
  - coding-assistant audit APIs
  - agent framework telemetry
- Join keys
  - agent_id
  - connector_id
  - session_id
  - tool
  - principal

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- gate an agent action that came from a non-interactive session
- revoke a connector grant
- put the agent process on an egress allowlist
- disable a poisoned MCP server

**How we demo it**

Drawn from deadbugz-mcp, clinejection, and gitlost-github-agentic. Feed a poisoned tool description to an agent, then gate its privileged action and contain its process. What it proves: The poisoned tool call is detected, the gated action is refused, the agent cannot read the credential files or reach the exfiltration endpoint, and a normal tool call still works.

**Risks.** The space moves fast and APIs are unstable; Prompt payloads are large and sensitive.

**Fallback.** Contain the agent as a process with the runtime feed and leave tool-level detection for later.

### `cloud-control-plane` - Cloud control plane and cloud identity

**Tier:** P1 first ninety days · **Category:** `cloud_control_plane` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** AWS CloudTrail and GuardDuty, Microsoft Azure Activity and Defender for Cloud, Google Cloud Audit Logs and SCC.

**Why here in the order.** It is the second half of the identity chain. Once an attacker owns an identity, the cloud control plane is how it reaches Key Vaults, storage, and VMs. We need it to see that move and to revoke the workload identity.

**Data we want**
- Events
  - control-plane API call
  - role assumption
  - key vault or storage access
  - metadata service call
  - policy change
  - anomalous region or user agent
- Fields
  - principal
  - assumed role
  - action
  - resource
  - source IP
  - user agent
  - session
  - error code
  - account and subscription
- APIs
  - CloudTrail and GuardDuty
  - Azure Activity and Entra logs
  - Google Cloud Audit Logs
- Join keys
  - principal
  - session_id
  - resource_id
  - role
  - workload_id

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- attach a deny policy to a session
- disable an access key
- revoke a role session
- apply an SCP or permission boundary

**How we demo it**

Drawn from storm2949-identity-cloud and salesloft-drift. Replay a compromised identity making control-plane calls toward a decoy key vault and storage account. What it proves: The control-plane anomaly is detected, the decoy resources absorb the access, the deny policy stops the session, and a benign admin action is unaffected.

**Risks.** High-privilege read scope; Control-plane log volume is large.

**Fallback.** Read-only logs with enforcement through the identity provider.

### `collaboration-canary` - Collaboration and email

**Tier:** P1 first ninety days · **Category:** `collaboration` · **Effort:** low · **Direction:** telemetry, enforcement, deception

**Examples:** Slack, Microsoft 365 and Exchange, Google Workspace and Drive, Confluence, Notion.

**Why here in the order.** These surfaces carry the breadcrumbs and the data that attackers go after next. A canary document or a honey credential in a share is easy to plant and gives a clean signal when it is touched, and the same feed shows the exfiltration attempt.

**Data we want**
- Events
  - file share
  - external share
  - message and file access
  - DLP match
  - login from a new device
  - mail rule creation
- Fields
  - principal
  - file id and name
  - share target
  - external domain
  - session id
  - device
  - DLP policy
  - message metadata
- APIs
  - Slack Audit Logs and Events
  - Microsoft Graph and audit logs
  - Google Drive Activity API
  - email gateway logs
- Join keys
  - principal
  - file_id
  - session_id
  - canary_id

**Blue capability.** detection, diversion, prevention.

**Actions it unlocks**
- revoke an external share
- watermark or restrict a file
- block a domain
- remove a malicious mail rule

**How we demo it**

Drawn from the identity and collab stages of openai-hacktron and klue-oauth-icarus. Plant a canary document in a shared drive and a honey credential in a message, then let the attacker identity touch them. What it proves: The touch produces a high-precision alert tied to the session, the share and the credential are revoked, and a legitimate user opening the same folder produces nothing.

**Risks.** Privacy and data handling, since content is sensitive; Planted canaries need lifecycle management.

**Fallback.** Read-only admin audit logs.

### `detection-response` - SIEM and SOAR

**Tier:** P1 first ninety days · **Category:** `detection_response` · **Effort:** low · **Direction:** telemetry, enforcement

**Examples:** Splunk, Microsoft Sentinel, Elastic, Tines, Torq, XSOAR.

**Why here in the order.** Our alerts are only useful when they reach the tools a security team already watches, and the response playbooks are the natural place to trigger containment. It is the integration that makes the product fit an existing workflow.

**Data we want**
- Events
  - our alerts and decisions
  - correlation lookups
  - case creation
  - playbook execution
- Fields
  - alert id
  - detection source
  - severity
  - run id
  - route and session keys
  - action taken
  - outcome
- APIs
  - Splunk HEC and saved searches
  - Sentinel ingestion and Logic Apps
  - Elastic ingest
  - SOAR playbook triggers
  - webhooks
- Join keys
  - run_id
  - incident_id
  - route_id
  - session_id
  - principal

**Blue capability.** detection, verification.

**Actions it unlocks**
- trigger a containment playbook
- open a case
- enrich an alert with asset and identity context

**How we demo it**

Drawn from any estate run. Push the D2, D4, D5, and D6 alerts from a parser-estate run into the SIEM and run a playbook. What it proves: The alerts arrive with the join keys intact, the playbook fires the containment action, and the re-attack result lands back on the same case.

**Risks.** Alert schema mapping per platform; Ingestion cost at volume.

**Fallback.** A webhook and a plain JSON schema that any platform can ingest.

### `endpoint-edr` - Endpoint detection and response

**Tier:** P1 first ninety days · **Category:** `runtime_enforcement` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, VMware Carbon Black.

**Why here in the order.** The npm and developer-tool incidents land on workstations, not servers. Endpoint telemetry is how we see a lifecycle script spawn a shell on a developer's machine, and it is where we can isolate the host.

**Data we want**
- Events
  - process execution
  - file creation
  - network connection
  - registry or launch agent change
  - device timeline
- Fields
  - device id
  - user
  - process tree
  - command line
  - file hash and path
  - destination
  - parent process
  - sensor verdict
- APIs
  - Falcon event streams
  - Defender advanced hunting
  - SentinelOne API
  - EDR response APIs
- Join keys
  - device_id
  - principal
  - pid and lineage
  - workload_id

**Blue capability.** detection, prevention, verification.

**Actions it unlocks**
- isolate the host
- kill the process tree
- quarantine the file
- run a remediation script

**How we demo it**

Drawn from axios-npm, chaindrop-npm-worm, and vscode-token-theft. Run the stand-in worm on a developer workstation image and watch the endpoint feed. What it proves: The lifecycle script and the credential file reads show up as a process lineage, the host isolates cleanly, and the clean install produces no alert.

**Risks.** Agent deployment and host access; Endpoint actions are disruptive.

**Fallback.** eBPF on the build runner, which covers most of the CI half.

## P2 later

### `asset-risk` - Asset inventory, vulnerability, and SBOM

**Tier:** P2 later · **Category:** `asset_risk` · **Effort:** medium · **Direction:** telemetry

**Examples:** ServiceNow CMDB, Wiz, Tenable, Snyk, CycloneDX and SPDX SBOMs.

**Why here in the order.** By itself it neither detects nor stops anything. It tells us where to put a decoy and how wide a control would land, which makes the loop safer at scale.

**Data we want**
- Events
  - asset inventory
  - ownership
  - exposure
  - vulnerability finding
  - dependency graph
- Fields
  - asset id
  - owner
  - technology
  - network exposure
  - CVE or finding
  - dependency path
  - criticality
- APIs
  - CMDB APIs
  - scanner APIs
  - SBOM files
  - cloud asset inventory
- Join keys
  - asset_id
  - workload_id
  - package_id
  - owner

**Blue capability.** verification.

**How we demo it**

Drawn from asset selection across the catalog. Before applying a control, ask which assets it would hit and which asset is worth decoying. What it proves: The blast-radius number is attached to the control decision, and the decoy lands on the asset an attacker would want.

**Risks.** Data quality, since stale inventories give wrong answers.

**Fallback.** A hand-maintained asset list for the demo estate.

### `threat-intel` - Threat intelligence and exploited-vulnerability feeds

**Tier:** P2 later · **Category:** `asset_risk` · **Effort:** low · **Direction:** telemetry

**Examples:** CISA KEV, vendor advisories, open-source IOC feeds, internal incident catalog.

**Why here in the order.** It decides what we emulate next, not what we block. We already keep a curated incident catalog in this repo, and a feed automates the refresh.

**Data we want**
- Events
  - new exploited vulnerability
  - new incident write-up
  - IOC
  - TTP
- Fields
  - CVE
  - product
  - date added
  - actor
  - TTP
  - source URL
- APIs
  - CISA KEV JSON
  - vendor advisory feeds
  - research blog feeds
- Join keys
  - cve
  - incident_id
  - ttp

**Blue capability.** verification.

**How we demo it**

Drawn from catalog maintenance. Refresh the incident catalog from the feed and pick the next estate to build. What it proves: The catalog stays current and every test estate traces to a real incident.

**Risks.** Feed noise; Duplicate incidents.

**Fallback.** The manual catalog in this repo.

### `network-enforcement` - Network policy and firewalls

**Tier:** P2 later · **Category:** `deception_route` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** Cloud security groups and NACLs, Kubernetes network policy, Cilium, Palo Alto, iptables and nftables.

**Why here in the order.** It is how we wall off the real estate once a canary fires and how we enforce an egress allowlist. It supports the diversion story and does not create it, so it sits after the proxy.

**Data we want**
- Events
  - flow log
  - policy decision
  - denied connection
  - DNS query
- Fields
  - source and destination IP
  - port
  - protocol
  - workload
  - policy rule
  - verdict
- APIs
  - VPC flow logs
  - Cilium and Calico policy APIs
  - firewall APIs
  - nftables
- Join keys
  - workload_id
  - route_id
  - destination

**Blue capability.** prevention, diversion, verification.

**Actions it unlocks**
- deny egress to a destination
- wall off the real target for a tainted session
- remove a route

**How we demo it**

Drawn from openai-hacktron and nextjs-libheif-avif. After the canary fires, deny the tainted workload any route to the real target and re-run the attack. What it proves: The attack is contained, the decoy is the only reachable service, and the held verdict comes from the real state.

**Risks.** A bad rule can cause an outage.

**Fallback.** Host-level egress policy through the runtime feed.

### `identity-governance` - SaaS security posture and CASB

**Tier:** P2 later · **Category:** `identity` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** Okta Identity Governance, Microsoft Defender for Cloud Apps, Netskope, AppOmni.

**Why here in the order.** It tells us which third-party apps hold which scopes, which is exactly the OAuth supply-chain risk in two catalog incidents. It is valuable context, but the core detection can run without it.

**Data we want**
- Events
  - connected app inventory
  - consent grant
  - scope change
  - dormant app
  - anomalous OAuth activity
- Fields
  - app id
  - scopes
  - users granted
  - publisher
  - last used
  - risk rating
- APIs
  - Okta apps and grants
  - Defender for Cloud Apps API
  - CASB APIs
- Join keys
  - app_id
  - principal
  - token_id
  - scope

**Blue capability.** detection, prevention.

**Actions it unlocks**
- revoke an OAuth app
- reduce scopes
- block a publisher

**How we demo it**

Drawn from klue-oauth-icarus and salesloft-drift. Inventory the connected apps, find the over-scoped integration, and revoke it during the replay. What it proves: The over-scoped app is found before the replay, the revoke removes the path, and the re-attack fails.

**Risks.** Read scope across all SaaS apps.

**Fallback.** Manual app inventory from the IdP.

### `pam-bastion` - Privileged access management and bastion

**Tier:** P2 later · **Category:** `identity` · **Effort:** medium · **Direction:** telemetry, enforcement

**Examples:** CyberArk, Teleport, HashiCorp Boundary, AWS SSM Session Manager.

**Why here in the order.** The admin path is a later hop in several chains. Recording privileged sessions and terminating one is useful, but it is not where the first three links live.

**Data we want**
- Events
  - privileged session start
  - session recording
  - command
  - credential checkout
  - approval
- Fields
  - principal
  - target host
  - session id
  - commands
  - approval id
  - duration
- APIs
  - PAM APIs and session recordings
  - SSM session logs
  - Teleport audit
- Join keys
  - principal
  - session_id
  - target
  - approval_id

**Blue capability.** detection, prevention.

**Actions it unlocks**
- terminate a live privileged session
- require approval
- rotate a checked-out credential

**How we demo it**

Drawn from the post-RCE admin stage. Replay an attacker using a checked-out credential on a bastion and terminate the session mid-chain. What it proves: The privileged session is recorded and cut, and the legitimate operator's session is untouched.

**Risks.** Cutting a session can interrupt remediation work.

**Fallback.** IdP session revocation.
