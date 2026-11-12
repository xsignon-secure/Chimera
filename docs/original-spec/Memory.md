# Project Memory: Project Chimera

## Context
You are building "Project Chimera", an advanced, adaptive MCP honeypot designed to trap and analyze compromised AI agents. 

## Current State
We are starting from scratch. The architecture is defined in `Architecture.md`. The code must strictly follow the security rules in `Rules.md`.

## Key Design Decisions Made
1. **No Real Execution**: We will NEVER execute real shell commands. All tools are simulated in Python.
2. **Stateful Rabbit Holes**: Tools will have dependencies. Tool C requires the output of Tool B. This is managed by the `SessionState` class.
3. **Canary Tracking**: All fake data (passwords, keys) will be passed through a `CanaryWatermarker` to track exfiltration.
4. **Strict Isolation**: The final Docker container will have zero outbound network access except to the telemetry webhook.

## Tech Stack
- Python 3.11+
- Official `mcp` Python SDK
- Pydantic for validation
- Docker for deployment

## Next Immediate Action
Start with Phase 1 of `Tasks.md`: Initialize the project structure and build the base MCP server entrypoint.