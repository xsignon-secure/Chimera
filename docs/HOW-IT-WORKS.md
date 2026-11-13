# How Chimera works

The full reference behind the [README](../README.md): the decoy, canaries, telemetry, the Blue Team responder, the security model, operations and known limits.


## The decoy

| Profile (`CHIMERA_PROFILE`) | Presents as | Highlights |
|---|---|---|
| `aws-prod-root` (default) | `AWS-Prod-Root-MCP` | root keys, IAM user creation, Vault, data export, shell |
| `internal-admin` | `Internal-Admin-Credentials-MCP` | admin passwords, SSH bastion key, SSO impersonation links, firewall disable |
| `full` | `Corp-Ops-Toolkit-MCP` | all 13 tools |

Everything the decoy says comes from a **fake world** derived from `CHIMERA_SEED`. That covers the company, employees, hosts (RFC 1918 only), AWS account and region. Answers stay consistent across calls and restarts, which defeats simple cross-checking, while no two deployments look alike. Responses use randomized latency and per-session personas (`stressed_sysadmin`, `by_the_book_ops`, `legacy_automation`). An optional local Ollama model can rephrase them.

**Rabbit hole.** `execute_data_export_script` and `read_vault_secret` require a Vault token. `refresh_vault_token` only accepts a password the honeypot previously issued. An attacker who follows the chain reveals intent at each step, and the exfiltration destination they supply is captured as an IOC.

**Fake shell.** `run_shell_command` emulates a bastion. `cat ~/.aws/credentials` returns fresh canaries, and `curl`/`wget` "time out" while the URL is recorded. Destructive commands silently "succeed" and change nothing. No command ever reaches the OS.

## Canaries

| Detection | How |
|---|---|
| **Reuse** | Any issued value appearing in a later request, from any session or IP, raises `canary.reused`. Reuse from a *different* session is critical (credential sharing or lateral movement). Every surface is scanned: MCP tool arguments, and on plain HTTP the query string, form or JSON body (a password typed into the decoy sign-in page), `Authorization` (Bearer and decoded Basic), `Cookie`, `X-API-Key`, `X-Vault-Token` and `X-Amz-Security-Token`. |
| **Callback** | Sign-in, impersonation and export links point back at the decoy. Opening one raises `canary.triggered` with the opener's IP: **high** from the IP that stole it, **medium** from anywhere else (a link-preview bot or a colleague must never trigger isolation on their own). |
| **External** | Load real Canarytokens AWS keys with `CHIMERA_CANARYTOKENS_FILE`. If the attacker uses one against AWS, canarytokens.org alerts you. `chimera canaries` shows which session stole that key. |

Get free AWS-key Canarytokens at <https://canarytokens.org>: choose *AWS keys*, download the credentials file, and concatenate several into one file. JSON lists are accepted too.

## Telemetry

Every MCP message (discovery, `tools/list`, calls, malformed requests) and every non-MCP HTTP probe becomes an ECS-style event. Each event carries `mitre_attack`, `mitre_atlas`, `canary_ids`, `fingerprint`, `indicators` (URLs, domains, IPs, emails, prompt-injection markers) and a SHA-256 of the raw params. Events are written to SQLite, `events.jsonl` and stdout **before** the attacker gets a response. Remote sinks are fed from background queues, one per sink, so a slow SIEM never creates a timing tell and an unreachable chat webhook never delays the containment alert to the responder.

Sign-in attempts on the decoy web page are recorded with the username (never the password, unless it is a canary) as `http.probe` events at medium severity, mapped to T1078 and T1110.

| Sink | Setting |
|---|---|
| JSONL file and stdout (ship with Filebeat, Vector, Fluent Bit) | always on |
| Signed webhook (HMAC-SHA256, replay-protected) | `CHIMERA_WEBHOOK_URL`, `CHIMERA_WEBHOOK_SECRET` |
| CEF over syslog (Splunk, QRadar, Wazuh, Graylog, Elastic) | `CHIMERA_SYSLOG_TARGET` |
| STIX 2.1 bundle per session (MISP, OpenCTI) | `chimera export-stix <session_id>` |

## The responder (Blue Team)

The responder keeps one incident per attacking source IP. When an incident reaches `RESPONDER_TRIGGER_SEVERITY`, what happens depends on the mode:

| `RESPONDER_MODE` | Behaviour |
|---|---|
| `dry_run` | Records exactly what it would do, and does nothing. |
| `approve` **(default)** | Waits for one click on the dashboard, or an `approve_isolation` call from a Blue Team agent. Slack/Discord gets a link. |
| `auto` | Isolates immediately. |

The following safety rails apply in every mode:
* `RESPONDER_PROTECTED_NETWORKS` are never isolated. Loopback is always protected.
* `RESPONDER_MAX_ISOLATIONS_PER_HOUR` caps automatic actions, so a flood of alerts cannot mass-isolate a network. The cap is counted from the audit log, so a restart does not reset it.
* A released or failed incident re-opens if the same host attacks again, and a dismissed one re-opens on a critical event, so a returning attacker is never silently ignored.
* Every decision, human or automatic, goes into an audit log.
* Dashboard actions require a per-incident nonce, which protects against CSRF and stale clicks.
* `RESPONDER_ISOLATION_TTL_HOURS` releases isolations automatically (the installer sets 7 days; 0 keeps them until an analyst releases). Attacker addresses are often cloud or residential IPs that later belong to someone innocent. A host that attacks again after release is contained again.
* IPv6 attackers are blocked as their whole /64, since one subscriber can rotate freely within it, and a /64 that touches a protected range is refused.
* After 20 failed dashboard sign-ins in a minute, sign-in pauses for a minute (HTTP 429), which caps password guessing through the public tunnel link.

Containment backends (`RESPONDER_ACTIONS`, all free):

| Action | What it does |
|---|---|
| `blocklist` | Maintains `/feeds/blocklist.txt` (send `Authorization: Bearer <RESPONDER_FEED_TOKEN>`, or `?token=…` for firewalls that cannot set headers). pfSense/OPNsense URL-table aliases, FortiGate external threat feeds, nginx, fail2ban and most firewalls can consume it. |
| `webhook` | Signed JSON to any SOAR (Shuffle, n8n, Tines community) for EDR host isolation or NAC quarantine. |
| `wazuh` | Calls the Wazuh 4.x API active-response endpoint, which drops the source IP in the firewall of the agents you choose. Tested end to end against a real Wazuh 4.14 manager and agent. A call that reaches zero agents is reported as a failure, never as isolated. |

**Blue Team MCP.** The responder also *is* an MCP server (`/mcp/`, bearer token `RESPONDER_MCP_TOKEN`), with tools `list_incidents`, `get_incident`, `approve_isolation`, `reject_isolation`, `release_isolation` and `get_audit_log`. A defender's AI agent can triage and act, with the same safety rails as the dashboard. Everything the attacker wrote (tool arguments, client names, messages) is returned under `untrusted_attacker_data` with an explicit notice, so an attacker cannot prompt-inject your defending agent through the evidence.

```bash
claude mcp add --transport http blueteam http://127.0.0.1:9000/mcp/ --header "Authorization: Bearer $RESPONDER_MCP_TOKEN"
```

---

## Security model

See [`docs/SECURITY.md`](SECURITY.md) for the full threat model. In short:

* **No execution.** There is no `subprocess`, `os.system`, `eval`, `exec` or `pickle` anywhere. A test parses every source file and fails the build if one appears.
* **No pivot, enforced twice.** First, in code: one egress guard allowlists outbound hosts, follows no redirects, ignores proxy environment variables, and never fetches attacker-supplied URLs (tested). Second, in the network: the honeypot only joins Docker `internal` networks, which have no route off the host. The ingress proxy and the responder are its only peers, and the responder accepts only `POST /api/alerts` from the honeypot's subnet (dashboard, feed and Blue Team MCP return 404). The honeypot container receives only its own `CHIMERA_*` settings, never the responder's passwords or tokens.
* **Hardened containers.** They run non-root (uid 10001) with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID, memory and CPU limits, and a tmpfs `/tmp`.
* **No real data.** Every secret is synthetic and every address is RFC 1918. Tool names and descriptions contain no "honeypot", "canary" or "fake" tells (tested).
* **Abuse resistance.** Rate limiting runs at nginx and in the app. Request bodies, client metadata and recorded arguments are size-capped, canaries per session are capped, storage is pruned automatically (`CHIMERA_RETENTION_DAYS`, `CHIMERA_MAX_EVENTS`), and `X-Forwarded-For` is trusted only from the configured proxy. Attacker text sent to Slack or Discord is escaped so it cannot ping `@channel` or plant links.

## Operations

```bash
docker compose exec honeypot chimera sessions            # attacker sessions with fingerprint and tools used
docker compose exec honeypot chimera canaries            # every tripwire handed out, and to whom
docker compose exec honeypot chimera export-stix <sid>   # STIX 2.1 bundle
docker compose exec honeypot chimera bait                # .mcp.json breadcrumb pointing at the decoy
docker compose logs -f honeypot                          # live JSON event stream
```

Back up the `honeypot-data` and `responder-data` volumes. Keep `CHIMERA_SEED` and `CHIMERA_CANARY_SECRET` stable for the life of the deployment. More detail is in [`docs/DEPLOYMENT.md`](DEPLOYMENT.md).

## Development

```bash
pip install -e ".[dev]"
pytest              # unit, end-to-end and security-gate tests
ruff check src tests && mypy src && bandit -ll -r src
```

## Known limits

* An MCP server sees tool calls and arguments, **not** the prompt the attacker's agent received. "Exact prompt" therefore means the exact call, plus any natural-language justification the agent writes into arguments (which Chimera captures and flags).
* The isolation target is the source IP the honeypot sees. Behind NAT or a shared egress, that is the NAT address. Add such addresses to `RESPONDER_PROTECTED_NETWORKS` and use the SOAR webhook to resolve the real host.
* Publish the decoy over IPv4. Docker forwards IPv6 clients (and any traffic through `docker-proxy`) from the edge gateway address, which hides the real source. The compose file protects Docker's own subnets so this can never isolate everyone, but you lose attribution for those clients.
* The Wazuh API cannot undo an active response. Use a timed command (see [`docs/DEPLOYMENT.md`](DEPLOYMENT.md#wazuh)) so blocks lift by themselves; with the bare `!firewall-drop` script a block is permanent until removed on the agent, and the dashboard says so on release.
* MCP SDK 2.x (`mcp>=2.3`) is required. Both the 2026 stateless protocol and legacy stateful clients (`initialize` handshake) are supported and tested.
