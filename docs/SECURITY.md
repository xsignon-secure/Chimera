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
| Full compromise of the honeypot process (e.g. a Python or SDK 0-day) | The container joins only Docker `internal: true` networks, so there is no route off the host. Its only peers are nginx (ingress) and the responder. It runs read-only, non-root, with no capabilities and `no-new-privileges`. | Manual check, recorded in the release notes: from inside the container, `example.com`, `1.1.1.1` and the Docker host were unreachable, while the responder was reachable |
| Forged alerts to the responder (to isolate a victim of the attacker's choosing) | HMAC-SHA256 over `timestamp.body` with ±300 s replay window. Event ids are de-duplicated. The responder is on an internal network, not the internet. | `test_blue_team_mcp` (missing, bad and stale signatures are rejected) |
| Spoofed `X-Forwarded-For` to frame another host | nginx **overwrites** the header with `$remote_addr`. The app trusts XFF only from the proxy's fixed IP (`CHIMERA_TRUSTED_PROXIES`). | `test_xff_only_trusted_from_proxy` |
| Alert flood leading to mass isolation | Protected networks are never isolated. An hourly cap stops automatic actions. The default mode needs one human approval. | `test_protected_and_rate_capped` |
| CSRF or stale clicks on the dashboard | HTTP Basic auth plus a per-incident nonce that rotates after every approval. A CSP blocks scripts and framing. | `test_attack_to_isolation` |
| Unauthenticated use of the Blue Team MCP | Bearer token is required. An empty token disables the endpoint. | `test_blue_team_mcp` |
| DoS / resource exhaustion | nginx rate and connection limits, plus an in-app per-IP limiter. Request bodies are capped at 512 KB, MCP sessions at 2,000, and per-session caches are bounded. Container memory, CPU and PID limits apply. | Code review |
| Honeypot fingerprinting by the attacker | Seeded, consistent fake world. RFC 1918 addresses only. Realistic formats (AKIA…, hvs.…, OpenSSH). Latency jitter. No tells in tool names or descriptions. No `Server` header. Health endpoint only answers on localhost. | `test_no_honeypot_tells_in_tool_surface`, `test_responses_contain_no_public_ips`, `test_formats_look_real` |
| Evidence loss | Events are persisted to SQLite and JSONL **before** the response is returned. Remote delivery is queued with retries. | `test_rabbit_hole_enforces_dependencies` (events present after calls) |
| Leaking real secrets | Every secret is HMAC-derived from a local key. External Canarytokens are tripwires by design and hold no access. | `test_every_returned_secret_is_a_registered_canary` |

## Residual risks and operator responsibilities

* **Placement.** Put the decoy where only an attacker would find it. If legitimate automation is pointed at it, you will generate true but unwanted alerts. That is still useful, because the automation is misconfigured, but tune `RESPONDER_MODE` accordingly.
* **NAT.** The source IP may be a NAT gateway. Protect such addresses and resolve the real host in your SOAR.
* **Syslog sink.** `CHIMERA_SYSLOG_TARGET` sends UDP directly from the honeypot. If you use it, attach the honeypot to a network that reaches only the collector, or relay through the responder's network.
* **Persona LLM.** If you enable the Ollama persona, its host joins the egress allowlist. Run Ollama on the internal `alerts` network, never on the internet.
* **Secrets.** Keep `.env` out of version control (it is already in `.gitignore`), and rotate `CHIMERA_WEBHOOK_SECRET` and the dashboard password like any other credential.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue.
