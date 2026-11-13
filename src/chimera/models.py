"""Typed records shared by the sensor, store, and telemetry pipeline."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from chimera.config import Severity

EventKind = Literal[
    "mcp.request",  # any JSON-RPC request (recon: discover, tools/list...)
    "mcp.tool_call",  # a honey tool was invoked
    "mcp.error",  # malformed or failing request
    "canary.issued",  # a tripwire was handed to an attacker
    "canary.reused",  # a tripwire came back inside a later request
    "canary.triggered",  # a tripwire was used out-of-band (callback hit / Canarytokens alert)
    "http.probe",  # non-MCP HTTP probing of the decoy
    "sensor.heartbeat",  # periodic liveness + delivery counters, honeypot -> responder only
]


def utcnow() -> datetime:
    return datetime.now(UTC)


class AgentFingerprint(BaseModel):
    client_name: str | None = None
    client_version: str | None = None
    protocol_version: str | None = None
    user_agent: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    classification: Literal["ai_agent", "mcp_client", "scanner", "script", "unknown"] = "unknown"
    confidence: float = 0.0
    signals: list[str] = Field(default_factory=list)


class Indicators(BaseModel):
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    prompt_injection_markers: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.urls or self.domains or self.ips or self.emails or self.prompt_injection_markers)


class Event(BaseModel):
    """One telemetry record. Field names follow ECS conventions where they exist."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=utcnow)
    kind: EventKind
    severity: Severity = "info"
    sensor: str = "chimera"
    profile: str = ""
    session_id: str = ""
    source_ip: str = ""
    source_port: int | None = None
    transport: Literal["streamable-http", "sse", "stdio", "http"] = "streamable-http"
    method: str | None = None
    tool: str | None = None
    arguments: dict[str, object] | None = None
    raw_params_sha256: str | None = None
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    response_summary: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    canary_ids: list[str] = Field(default_factory=list)
    fingerprint: AgentFingerprint | None = None
    indicators: Indicators | None = None
    persona: str | None = None
    message: str = ""

    def compact(self) -> Event:
        """A small copy that always fits a sink's size limit (keeps the decision-relevant fields)."""
        fp = self.fingerprint.model_copy(update={"signals": self.fingerprint.signals[:5]}) if self.fingerprint else None
        return self.model_copy(
            update={
                "arguments": {"_omitted": "too large; see local events.jsonl"} if self.arguments else None,
                "response_summary": None,
                "fingerprint": fp,
                "indicators": None,
                "message": self.message[:500],
            }
        )


class CanaryRecord(BaseModel):
    canary_id: str
    kind: str
    value: str
    session_id: str
    source_ip: str
    tool: str
    issued_at: datetime = Field(default_factory=utcnow)
    external: bool = False
    """True when the value is a real third-party tripwire (e.g. canarytokens.org)."""


class SessionSummary(BaseModel):
    session_id: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    request_count: int
    tool_calls: list[str]
    max_severity: Severity
    fingerprint: AgentFingerprint | None = None
