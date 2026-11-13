"""Runtime configuration, loaded from ``CHIMERA_*`` environment variables.

Every setting has a safe default so the honeypot starts with zero configuration
in local mode: telemetry goes to a JSONL file and stdout, and no outbound
network traffic is attempted until an allowlisted webhook is configured.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"CHIMERA_{name}", default).strip()


def _env_list(name: str) -> list[str]:
    raw = _env(name)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    """All honeypot settings. Build with :meth:`from_env`."""

    profile: str = "aws-prod-root"
    # Binds all interfaces because it runs inside an isolated container network.
    host: str = "0.0.0.0"  # nosec B104
    port: int = 8000
    mcp_path: str = "/mcp"
    public_base_url: str = "http://localhost:8000"
    """Externally reachable base URL, used to build canary callback links."""

    data_dir: Path = Path("./chimera-data")
    seed: str = Field(default_factory=lambda: secrets.token_hex(16))
    """Seed for the fake world. Fix it per deployment so the decoy stays consistent."""

    canary_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    """HMAC key used to derive canary identifiers. Keep stable across restarts."""

    trusted_proxies: list[str] = Field(default_factory=list)
    """CIDRs whose X-Forwarded-For header is trusted (the ingress proxy)."""

    # Telemetry sinks
    log_stdout: bool = True
    webhook_url: str = ""
    webhook_secret: str = ""
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    syslog_target: str = ""
    """``host:port`` for CEF over UDP syslog (Splunk, QRadar, Wazuh, Graylog...)."""

    egress_allowlist: list[str] = Field(default_factory=list)
    """Hostnames the honeypot may contact. Webhook hosts are added automatically."""

    heartbeat_seconds: int = 60
    """How often the honeypot tells the responder it is alive (0 disables). Lets the responder
    alert when the sensor goes silent, and report alert-delivery health on its metrics page."""

    alert_min_severity: Severity = "medium"

    # Retention (bounded disk use)
    retention_days: int = 90
    max_events: int = 2_000_000
    canary_retention_days: int = 180
    max_canaries: int = 500_000

    # Per-install identity: override the profile's advertised server name / version so
    # deployments never share a fingerprint.
    server_name: str = ""
    server_version: str = ""

    # Deception behaviour
    latency_min_ms: int = 120
    latency_max_ms: int = 900
    rate_limit_per_minute: int = 120
    canarytokens_file: Path | None = None
    """Optional JSON file of real Canarytokens (e.g. AWS keys from canarytokens.org)."""

    persona_llm_url: str = ""
    """Optional local Ollama endpoint for persona flavour text, e.g. http://ollama:11434."""
    persona_llm_model: str = "llama3.2:1b"

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            ipaddress.ip_network(cidr, strict=False)
        return value

    @model_validator(mode="after")
    def _reject_placeholders(self) -> Settings:
        for name in ("webhook_secret", "seed", "canary_secret"):
            if "change-me" in getattr(self, name):
                raise ValueError(f"CHIMERA_{name.upper()} still has its placeholder value; generate a real secret")
        return self

    @model_validator(mode="after")
    def _derive_allowlist(self) -> Settings:
        hosts = set(self.egress_allowlist)
        for url in (self.webhook_url, self.slack_webhook_url, self.discord_webhook_url, self.persona_llm_url):
            if url:
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ValueError(f"invalid outbound URL: {url!r}")
                hosts.add(parsed.hostname.lower())
        self.egress_allowlist = sorted(hosts)
        return self

    @property
    def db_path(self) -> Path:
        return self.data_dir / "chimera.db"

    @property
    def events_path(self) -> Path:
        return self.data_dir / "events.jsonl"

    @classmethod
    def from_env(cls) -> Settings:
        values: dict[str, object] = {}
        mapping = {
            "profile": "PROFILE",
            "host": "HOST",
            "mcp_path": "MCP_PATH",
            "public_base_url": "PUBLIC_BASE_URL",
            "seed": "SEED",
            "canary_secret": "CANARY_SECRET",
            "webhook_url": "WEBHOOK_URL",
            "webhook_secret": "WEBHOOK_SECRET",
            "slack_webhook_url": "SLACK_WEBHOOK_URL",
            "discord_webhook_url": "DISCORD_WEBHOOK_URL",
            "syslog_target": "SYSLOG_TARGET",
            "alert_min_severity": "ALERT_MIN_SEVERITY",
            "persona_llm_url": "PERSONA_LLM_URL",
            "persona_llm_model": "PERSONA_LLM_MODEL",
            "server_name": "SERVER_NAME",
            "server_version": "SERVER_VERSION",
        }
        for field, env in mapping.items():
            raw = _env(env)
            if raw:
                values[field] = raw
        for field, env in {
            "port": "PORT",
            "latency_min_ms": "LATENCY_MIN_MS",
            "latency_max_ms": "LATENCY_MAX_MS",
            "rate_limit_per_minute": "RATE_LIMIT_PER_MINUTE",
            "retention_days": "RETENTION_DAYS",
            "max_events": "MAX_EVENTS",
            "canary_retention_days": "CANARY_RETENTION_DAYS",
            "max_canaries": "MAX_CANARIES",
            "heartbeat_seconds": "HEARTBEAT_SECONDS",
        }.items():
            raw = _env(env)
            if raw:
                values[field] = int(raw)
        if _env("DATA_DIR"):
            values["data_dir"] = Path(_env("DATA_DIR"))
        if _env("CANARYTOKENS_FILE"):
            values["canarytokens_file"] = Path(_env("CANARYTOKENS_FILE"))
        values["trusted_proxies"] = _env_list("TRUSTED_PROXIES")
        values["egress_allowlist"] = _env_list("EGRESS_ALLOWLIST")
        values["log_stdout"] = _env_bool("LOG_STDOUT", True)
        settings = cls.model_validate(values)
        settings.ensure_persistent_keys(seed_given="seed" in values, secret_given="canary_secret" in values)
        return settings

    def ensure_persistent_keys(self, seed_given: bool, secret_given: bool) -> None:
        """Persist auto-generated seed/secret so the fake world survives restarts."""
        if seed_given and secret_given:
            return
        path = self.data_dir / "keys.json"
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            stored = json.loads(path.read_text()) if path.exists() else {}
            if not seed_given:
                self.seed = stored.setdefault("seed", self.seed)
            if not secret_given:
                self.canary_secret = stored.setdefault("canary_secret", self.canary_secret)
            path.write_text(json.dumps(stored))
            path.chmod(0o600)
        except OSError:
            pass  # read-only data dir: fall back to per-process keys
