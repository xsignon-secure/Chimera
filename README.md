# Project Chimera

**A deception-driven MCP honeypot that traps compromised AI agents, tracks every secret they steal, and hands your Blue Team a one-click (or fully automatic) containment button.**

Chimera poses as a high-value internal MCP server such as `AWS-Prod-Root-MCP` or `Internal-Admin-Credentials-MCP`. Legitimate users have no reason to touch it, so any connection is a high-fidelity signal. When an attacker or a prompt-injected AI agent calls its tools, Chimera:

1. **Records everything** before it answers: source IP (proxy-aware), timestamp, the exact JSON-RPC call and arguments, client identity, and an AI-agent fingerprint.
2. **Feeds realistic fake data where every secret is a tripwire.** It issues AWS keys, passwords, SSH keys, Vault tokens, DB URLs, JWTs and sign-in links, each one unique to that session. Reuse anywhere is detected and attributed. It can also serve real [Canarytokens](https://canarytokens.org) AWS keys (free), so use against real AWS alerts you too.
3. **Drives containment** through a separate Blue Team responder. The responder sends signed alerts and correlates them into incidents. Containment is one-click by default (dashboard or Blue Team MCP tool), or automatic. It supports a firewall blocklist feed, Wazuh active response, SOAR webhooks, and Slack/Discord.

It never executes anything, and it runs on a network that has **no route out**, so it cannot be used as a pivot.

```
attacker / hijacked agent ──MCP──► ingress (nginx) ──► Chimera honeypot ──signed alert──► Responder ──► blocklist feed / Wazuh / SOAR / Slack
                                    published port      internal-only nets               dashboard + Blue Team MCP
                                                        no internet egress               one-click or auto isolation
```

---

## Why Chimera

We reviewed the open-source MCP honeypots that exist today (HoneyMCP, honeymcp, wasphole, MirageMCP, agent-honeypot, Beelzebub). Each does part of the job. Chimera's aim is to close the loop from *bait* to *containment*:

_"Typical" means most of the six we reviewed. Individual projects are stronger on single rows: agent-honeypot has a deeper 24-signal fingerprint model, and Beelzebub covers many protocols besides MCP._

| Capability | Chimera | Typical MCP honeypot |
|---|---|---|
| Tempting, profile-based decoy (AWS root, admin creds, ops toolkit) | ✅ 3 profiles, 13 tools | ✅ |
| Multi-step "rabbit hole" (creds → Vault token → secrets → export) | ✅ enforced per session | rare |
| Every secret is a unique, attributable canary | ✅ 8 formats + URL callbacks | partial |
| Real third-party tripwires (Canarytokens AWS keys) | ✅ | ❌ |
| Cross-session reuse detection (credential sharing / lateral movement) | ✅ | rare |
| AI-agent fingerprinting (client, capabilities, LLM think-time, NL justifications) | ✅ | shallow |
| Prompt-injection markers in tool arguments | ✅ | rare |
| MITRE ATT&CK **and** ATLAS per event | ✅ | one or neither |
| SIEM outputs: JSONL, CEF/syslog, signed webhook, STIX 2.1 | ✅ | partial |
| **Automated containment loop** (dry-run / one-click / auto) with safety rails | ✅ | ❌ |
| **Blue Team MCP server** so a defender's AI agent can triage and act | ✅ | ❌ |
| Network-enforced no-pivot deployment plus tested code guarantees | ✅ | rare |
| Cost | **$0**: Python, SQLite, Docker, nginx, free integrations | varies |

---

## Quick start (Docker, recommended)

Requirements: Docker with Compose v2. Nothing else, and no paid services.

```bash
cp .env.example .env
# Edit .env: set the five REQUIRED values (secrets, dashboard password, public URL, seed)
docker compose up -d --build
```

* Decoy MCP endpoint: `http://<host>:8000/mcp`. Announce it the way a real internal server would be, for example in an internal MCP registry, a `.mcp.json` in a tempting repo, or a wiki page.
* Responder dashboard: `http://127.0.0.1:9000` (user `admin`). It is bound to localhost by default, so reach it over SSH or VPN.

### Try it in two minutes

Point any MCP client at the decoy. With Claude Code:

```bash
claude mcp add --transport http aws-prod http://127.0.0.1:8000/mcp
```

Ask the agent to "get the break-glass Vault password". Then open the dashboard: you'll see the incident, the fingerprint (`claude-code`, classified `ai_agent`), the MITRE techniques, the canaries it was handed, and an **Isolate** button.

### Local, without Docker

```bash
pip install .
chimera serve --profile internal-admin          # HTTP on :8000
chimera serve --transport stdio                 # for stdio-based clients
chimera-responder                               # Blue Team service on :9000
```

---

## How it works

### The decoy

| Profile (`CHIMERA_PROFILE`) | Presents as | Highlights |
|---|---|---|
| `aws-prod-root` (default) | `AWS-Prod-Root-MCP` | root keys, IAM user creation, Vault, data export, shell |
| `internal-admin` | `Internal-Admin-Credentials-MCP` | admin passwords, SSH bastion key, SSO impersonation links, firewall disable |
| `full` | `Corp-Ops-Toolkit-MCP` | all 13 tools |

Everything the decoy says comes from a **fake world** derived from `CHIMERA_SEED`. That covers the company, employees, hosts (RFC 1918 only), AWS account and region. Answers stay consistent across calls and restarts, which defeats simple cross-checking, while no two deployments look alike. Responses use randomized latency and per-session personas (`stressed_sysadmin`, `by_the_book_ops`, `legacy_automation`). An optional local Ollama model can rephrase them.

**Rabbit hole.** `execute_data_export_script` and `read_vault_secret` require a Vault token. `refresh_vault_token` only accepts a password the honeypot previously issued. An attacker who follows the chain reveals intent at each step, and the exfiltration destination they supply is captured as an IOC.

**Fake shell.** `run_shell_command` emulates a bastion. `cat ~/.aws/credentials` returns fresh canaries, and `curl`/`wget` "time out" while the URL is recorded. Destructive commands silently "succeed" and change nothing. No command ever reaches the OS.

### Canaries

| Detection | How |
|---|---|
| **Reuse** | Any issued value appearing in a later request, from any session or IP, raises `canary.reused`. Reuse from a *different* session is critical (credential sharing or lateral movement). |
| **Callback** | Sign-in, impersonation and export links point back at the decoy. Opening one raises `canary.triggered` with the opener's IP. |
| **External** | Load real Canarytokens AWS keys with `CHIMERA_CANARYTOKENS_FILE`. If the attacker uses one against AWS, canarytokens.org alerts you. `chimera canaries` shows which session stole that key. |

Get free AWS-key Canarytokens at <https://canarytokens.org>: choose *AWS keys*, download the credentials file, and concatenate several into one file. JSON lists are accepted too.

### Telemetry

Every MCP message (discovery, `tools/list`, calls, malformed requests) and every non-MCP HTTP probe becomes an ECS-style event. Each event carries `mitre_attack`, `mitre_atlas`, `canary_ids`, `fingerprint`, `indicators` (URLs, domains, IPs, emails, prompt-injection markers) and a SHA-256 of the raw params. Events are written to SQLite, `events.jsonl` and stdout **before** the attacker gets a response. Remote sinks are fed from a background queue, so a slow SIEM never creates a timing tell.

| Sink | Setting |
|---|---|
| JSONL file and stdout (ship with Filebeat, Vector, Fluent Bit) | always on |
| Signed webhook (HMAC-SHA256, replay-protected) | `CHIMERA_WEBHOOK_URL`, `CHIMERA_WEBHOOK_SECRET` |
| CEF over syslog (Splunk, QRadar, Wazuh, Graylog, Elastic) | `CHIMERA_SYSLOG_TARGET` |
| STIX 2.1 bundle per session (MISP, OpenCTI) | `chimera export-stix <session_id>` |

### The responder (Blue Team)

The responder keeps one incident per attacking source IP. When an incident reaches `RESPONDER_TRIGGER_SEVERITY`, what happens depends on the mode:

| `RESPONDER_MODE` | Behaviour |
|---|---|
| `dry_run` | Records exactly what it would do, and does nothing. |
| `approve` **(default)** | Waits for one click on the dashboard, or an `approve_isolation` call from a Blue Team agent. Slack/Discord gets a link. |
| `auto` | Isolates immediately. |

The following safety rails apply in every mode:
* `RESPONDER_PROTECTED_NETWORKS` are never isolated. Loopback is always protected.
* `RESPONDER_MAX_ISOLATIONS_PER_HOUR` caps automatic actions, so a flood of alerts cannot mass-isolate a network.
* Every decision, human or automatic, goes into an audit log.
* Dashboard actions require a per-incident nonce, which protects against CSRF and stale clicks.

Containment backends (`RESPONDER_ACTIONS`, all free):

| Action | What it does |
|---|---|
| `blocklist` | Maintains `/feeds/blocklist.txt?token=…`. pfSense/OPNsense URL-table aliases, FortiGate external threat feeds, nginx, fail2ban and most firewalls can consume it. |
| `webhook` | Signed JSON to any SOAR (Shuffle, n8n, Tines community) for EDR host isolation or NAC quarantine. |
| `wazuh` | Calls the Wazuh 4.x API active-response endpoint (default `!firewall-drop` against the source IP on the agents you choose). |

**Blue Team MCP.** The responder also *is* an MCP server (`/mcp/`, bearer token `RESPONDER_MCP_TOKEN`), with tools `list_incidents`, `get_incident`, `approve_isolation`, `reject_isolation`, `release_isolation` and `get_audit_log`. A defender's AI agent can triage and act, with the same safety rails as the dashboard.

```bash
claude mcp add --transport http blueteam http://127.0.0.1:9000/mcp/ --header "Authorization: Bearer $RESPONDER_MCP_TOKEN"
```

---

## Security model

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model. In short:

* **No execution.** There is no `subprocess`, `os.system`, `eval`, `exec` or `pickle` anywhere. A test parses every source file and fails the build if one appears.
* **No pivot, enforced twice.** First, in code: one egress guard allowlists outbound hosts, follows no redirects, ignores proxy environment variables, and never fetches attacker-supplied URLs (tested). Second, in the network: the honeypot only joins Docker `internal` networks, which have no route off the host. The ingress proxy and the responder are its only peers.
* **Hardened containers.** They run non-root (uid 10001) with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID, memory and CPU limits, and a tmpfs `/tmp`.
* **No real data.** Every secret is synthetic and every address is RFC 1918. Tool names and descriptions contain no "honeypot", "canary" or "fake" tells (tested).
* **Abuse resistance.** Rate limiting runs at nginx and in the app. Request body size is capped, session caches are bounded, and `X-Forwarded-For` is trusted only from the configured proxy.

## Operations

```bash
docker compose exec honeypot chimera sessions            # attacker sessions with fingerprint and tools used
docker compose exec honeypot chimera canaries            # every tripwire handed out, and to whom
docker compose exec honeypot chimera export-stix <sid>   # STIX 2.1 bundle
docker compose logs -f honeypot                          # live JSON event stream
```

Back up the `honeypot-data` and `responder-data` volumes. Keep `CHIMERA_SEED` and `CHIMERA_CANARY_SECRET` stable for the life of the deployment. More detail is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Development

```bash
pip install -e ".[dev]"
pytest              # unit, end-to-end and security-gate tests
ruff check src tests && mypy src && bandit -ll -r src
```

## Known limits

* An MCP server sees tool calls and arguments, **not** the prompt the attacker's agent received. "Exact prompt" therefore means the exact call, plus any natural-language justification the agent writes into arguments (which Chimera captures and flags).
* The isolation target is the source IP the honeypot sees. Behind NAT or a shared egress, that is the NAT address. Add such addresses to `RESPONDER_PROTECTED_NETWORKS` and use the SOAR webhook to resolve the real host.
* The Wazuh integration follows the Wazuh 4.x API documentation but has not been exercised against a live Wazuh manager in this release. Run it in `dry_run` or `approve` mode first.
* MCP SDK 2.x (`mcp>=2.3`) is required. Both the 2026 stateless protocol and legacy stateful clients (`initialize` handshake) are supported and tested.

## License

Apache-2.0
