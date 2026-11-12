# Product Requirements Document: Project Chimera (Adaptive Deception MCP)

## 1. Vision
Project Chimera is an advanced, adaptive Model Context Protocol (MCP) server designed to act as a high-fidelity honeypot for compromised AI agents and malicious human operators. It moves beyond static deception by dynamically adapting its persona, tracking data exfiltration via cryptographic canaries, and forcing attackers into multi-stage "rabbit holes."

## 2. Core Objectives
- **Detect Rogue AI Agents**: Identify when an LLM has been prompt-injected and is attempting to use MCP tools for unauthorized data access.
- **Profile Adversary TTPs**: Automatically map attacker interactions to the MITRE ATT&CK framework in real-time.
- **Track Exfiltration**: Ensure that any fake data stolen is uniquely watermarked so we can track where it ends up.

## 3. Target Audience
- Blue Team / SOC Analysts
- AI Security Researchers
- Red Teamers testing AI agent guardrails

## 4. Key Features (MVP & Advanced)
### MVP (Phase 1)
- Standard MCP server implementation (Python, `mcp` SDK).
- 5 core "Honey Tools" (e.g., `get_db_creds`, `list_admin_users`).
- JSON-based telemetry logging to a local file/webhook.

### Advanced (Phase 2 - The "Unique" Factor)
- **Persona Shifting Engine**: Internal LLM wrapper to adjust the tone and content of fake responses based on the attacker's prompt.
- **Canary Watermarking**: Injecting unique UUIDs/hashes into all returned fake strings (passwords, URLs, IPs).
- **Stateful Rabbit Holes**: Tools that require outputs from previous tools as inputs, creating a dependency graph of deception.
- **MITRE Auto-Mapper**: A middleware that intercepts tool calls and appends `mitre_technique_id` to the telemetry payload.

## 5. Success Metrics
- Zero real system compromise (100% isolation).
- Generation of high-fidelity alerts with < 5% false positive rate.
- Successful tracking of at least one exfiltrated canary payload in testing.