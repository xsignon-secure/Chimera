# Architecture Document: Project Chimera

## 1. High-Level Architecture
Chimera is built as a containerized, strictly isolated Python application communicating via the MCP standard I/O (stdio) or HTTP/SSE transport.

```text
[ Compromised AI Agent / Attacker ]
          | (MCP Protocol - JSON-RPC)
          v
+---------------------------------------+
|  Chimera MCP Server (Docker Container)|
|  +---------------------------------+  |
|  | 1. MCP Router & Validator       |  |
|  +---------------------------------+  |
|  | 2. State Machine (Rabbit Hole)  |  |
|  +---------------------------------+  |
|  | 3. Persona Engine (Lite LLM)    |  |
|  +---------------------------------+  |
|  | 4. Canary Watermark Generator   |  |
|  +---------------------------------+  |
|  | 5. Telemetry & MITRE Mapper     |  |
|  +---------------------------------+  |
+---------------------------------------+
          | (Outbound HTTPS - STRICTLY ALLOWLISTED)
          v
[ SIEM / Webhook / Discord Alert Channel ]