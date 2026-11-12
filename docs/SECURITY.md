# Security model and threat model

A honeypot is software you deliberately expose to hostile users. This document covers what Chimera defends against, how it does so, and what is tested.

## Assets

1. **Your real network.** The honeypot must never become a stepping stone into it (no pivot).
2. **The integrity of containment.** An attacker must not be able to make the responder isolate the wrong host.
3. **The secrecy of the deception.** The decoy should not reveal itself as a honeypot.
4. **The evidence.** Telemetry must be recorded even if the attacker crashes the session.

## Threats and controls

| Threat | Control | Verified by |
|---|---|---|
| Attacker gets code execution through a tool (`run_shell_command`, crafted args) | Tools are pure Python string logic. There are no `subprocess`, `os.system`, `eval`, `exec`, `compile`, `pickle`, `marshal` or `ctypes` calls. | `tests/test_security.py::test_no_code_execution_primitives` parses every source file (AST) |
| Honeypot used as an SSRF / pivot (export URLs, `curl` in fake shell) | Attacker URLs are only recorded, never fetched. All outbound HTTP goes through `EgressGuard`, which uses a host allowlist, follows no redirects and sets `trust_env=False`. | `test_attacker_urls_are_never_fetched`, `test_egress_guard_*` |
| Full compromise of the honeypot process (e.g. a Python or SDK 0-day) | The container joins only Docker `internal: true` networks, so there is no route off the host. Its only peers are nginx (ingress) and the responder, and the responder answers that subnet on `POST /api/alerts` only (`RESPONDER_ALERTS_ONLY_NETWORKS`). The container holds no responder secrets (no `env_file`). It runs read-only, non-root, with no capabilities and `no-new-privileges`. | `test_alerts_only_network_cannot_reach_console`, `test_compose_keeps_responder_secrets_out_of_the_honeypot`, plus a live check from inside the container: `example.com`, `1.1.1.1` and the Docker host unreachable; responder dashboard 404 |
| Forged alerts to the responder (to isolate a victim of the attacker's choosing) | HMAC-SHA256 over `timestamp.body` with ±300 s replay window. Event ids are de-duplicated. The responder is on an internal network, not the internet. | `test_blue_team_mcp` (missing, bad and stale signatures are rejected) |
| Spoofed `X-Forwarded-For` to frame another host | nginx **overwrites** the header with `$remote_addr`. The app trusts XFF only from the proxy's fixed IP (`CHIMERA_TRUSTED_PROXIES`). | `test_xff_only_trusted_from_proxy` |
| Alert flood leading to mass isolation | Protected networks (including Docker's own subnets) are never isolated. An hourly cap, counted from the persistent audit log, stops automatic actions. The default mode needs one human approval. | `test_protected_and_rate_capped`, `test_isolation_cap_survives_restart` |
| Framing an innocent host through a URL canary (pasting the link where a bot or colleague opens it) | A callback from any IP other than the thief's is `medium`, below the default trigger, and says why. | `test_link_preview_fetch_from_other_ip_is_not_high` |
| Attacker returns after release, or is wrongly dismissed | Released and failed incidents re-open on new qualifying activity; dismissed ones re-open on a critical event. An isolated incident must be released before it can be dismissed. | `test_released_attacker_who_returns_is_contained_again`, `test_release_and_reject_respect_state` |
| Prompt injection of the defender's AI agent through evidence | Blue Team MCP returns all attacker-written data under `untrusted_attacker_data` with a notice; server instructions say the same. | `test_blue_team_mcp` |
| Chat injection (`@channel`, links, formatting) via Slack/Discord alerts | All attacker text is escaped; Discord `allowed_mentions` is empty. | `test_chat_text_neutralises_mentions_and_links` |
| CSRF or stale clicks on the dashboard | HTTP Basic auth plus a per-incident nonce that rotates after every approval. A CSP blocks scripts and framing. | `test_attack_to_isolation` |
| Unauthenticated use of the Blue Team MCP | Bearer token is required. An empty token disables the endpoint. Credential checks compare bytes in constant time, so malformed or non-ASCII headers get 401, never a 500. Placeholder secrets from `.env.example` are refused at start-up. | `test_blue_team_mcp`, `test_non_ascii_credentials_get_401_not_500`, `test_placeholders_are_rejected` |
| DoS / resource exhaustion | nginx rate and connection limits (429), plus an in-app per-IP limiter. The MCP endpoint is stateless, so there is no session table to fill. Request bodies are capped at 512 KB; client metadata and recorded arguments are clipped; canaries per session are capped at 120; canary scanning uses a prefix index (linear time); events, canaries and JSONL files are pruned and rotated. Container memory, CPU and PID limits apply. | `test_canary_scan_cost_is_linear_and_bounded`, `test_per_session_canary_cap_reuses_existing`, `test_huge_arguments_are_bounded_in_evidence`, `test_fingerprint_clips_attacker_fields`, `test_store_prune_bounds_disk` |
| Honeypot fingerprinting by the attacker | Seeded, consistent fake world. RFC 1918 addresses only. Realistic formats (AKIA…, hvs.…, parseable OpenSSH Ed25519 keys, S3-style XML errors). The same question returns the same secret. A fake shell with pipes, variables and common files. Latency jitter. Per-install server name (`CHIMERA_SERVER_NAME`). No tells in tool names or descriptions. No `Server` header. Health endpoint only answers on localhost. | `test_no_honeypot_tells_in_tool_surface`, `test_responses_contain_no_public_ips`, `test_formats_look_real`, `test_ssh_key_is_a_real_parseable_openssh_key`, `test_same_question_gets_same_canary`, `test_fake_shell_pipes_and_variables` |
| Evidence loss | Events are persisted to SQLite and JSONL **before** the response is returned. Remote delivery is queued with retries. | `test_rabbit_hole_enforces_dependencies` (events present after calls) |
| Leaking real secrets | Every secret is HMAC-derived from a local key. External Canarytokens are tripwires by design and hold no access. | `test_every_returned_secret_is_a_registered_canary` |

## Residual risks and operator responsibilities

* **Placement.** Put the decoy where only an attacker would find it. If legitimate automation is pointed at it, you will generate true but unwanted alerts. That is still useful, because the automation is misconfigured, but tune `RESPONDER_MODE` accordingly.
* **NAT.** The source IP may be a NAT gateway. Protect such addresses and resolve the real host in your SOAR.
* **IPv6 and docker-proxy.** Clients that reach a published Docker port over IPv6 appear as the edge gateway. Docker's subnets are protected so this can never isolate everyone, but publish over IPv4 to keep attribution.
* **Syslog sink.** `CHIMERA_SYSLOG_TARGET` sends UDP directly from the honeypot. If you use it, attach the honeypot to a network that reaches only the collector, or relay through the responder's network.
* **Persona LLM.** If you enable the Ollama persona, its host joins the egress allowlist. Run Ollama on the internal `alerts` network, never on the internet.
* **Secrets.** Keep `.env` out of version control (it is already in `.gitignore`), and rotate `CHIMERA_WEBHOOK_SECRET` and the dashboard password like any other credential.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue.
