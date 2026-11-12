"""Responder settings, from ``RESPONDER_*`` environment variables."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator

Mode = Literal["dry_run", "approve", "auto"]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"RESPONDER_{name}", default).strip()


class ResponderSettings(BaseModel):
    # Binds all interfaces because it runs inside an isolated container network.
    host: str = "0.0.0.0"  # nosec B104
    port: int = 9000
    data_dir: Path = Path("./responder-data")
    mode: Mode = "approve"
    """dry_run: record what would happen. approve: one-click analyst approval. auto: act immediately."""
    trigger_severity: Literal["medium", "high", "critical"] = "high"
    honeypot_secret: str = ""
    """Shared HMAC secret; must equal CHIMERA_WEBHOOK_SECRET."""
    admin_password: str = ""
    """Password for the dashboard (HTTP Basic, user 'admin')."""
    mcp_token: str = ""
    """Bearer token for the Blue Team MCP endpoint."""
    feed_token: str = ""
    """Token for the blocklist feed (``/feeds/blocklist.txt?token=...``). Empty disables the feed."""
    protected_networks: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    """Addresses that must never be isolated (gateways, DNS, the SIEM itself...)."""
    alerts_only_networks: list[str] = Field(default_factory=list)
    """Source networks (e.g. the honeypot's alerts subnet) that may only POST /api/alerts.
    Requests from them to the dashboard, MCP endpoint or feed get 404, so a compromised
    honeypot cannot reach the Blue Team console."""
    max_isolations_per_hour: int = 10
    actions: list[str] = Field(default_factory=lambda: ["blocklist"])
    """Any of: blocklist, webhook, wazuh."""
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    """Analyst notifications (new incident awaiting approval, isolation done)."""
    action_webhook_url: str = ""
    action_webhook_secret: str = ""
    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""
    wazuh_command: str = "!firewall-drop"
    wazuh_agents: str = "all"
    wazuh_verify_tls: bool = True
    public_url: str = "http://localhost:9000"

    @model_validator(mode="after")
    def _check(self) -> ResponderSettings:
        for cidr in (*self.protected_networks, *self.alerts_only_networks):
            ipaddress.ip_network(cidr, strict=False)
        for name in ("honeypot_secret", "admin_password", "mcp_token", "feed_token", "action_webhook_secret"):
            if "change-me" in getattr(self, name).lower():
                raise ValueError(f"RESPONDER_{name.upper()} still holds the placeholder from .env.example")
        unknown = set(self.actions) - {"blocklist", "webhook", "wazuh"}
        if unknown:
            raise ValueError(f"unknown actions: {sorted(unknown)}")
        return self

    @property
    def egress_hosts(self) -> list[str]:
        return sorted(
            {
                urlsplit(u).hostname or ""
                for u in (self.action_webhook_url, self.wazuh_url, self.slack_webhook_url, self.discord_webhook_url)
                if u
            }
            - {""}
        )

    @classmethod
    def from_env(cls) -> ResponderSettings:
        v: dict[str, object] = {}
        for field in (
            "host",
            "mode",
            "trigger_severity",
            "honeypot_secret",
            "admin_password",
            "mcp_token",
            "feed_token",
            "action_webhook_url",
            "slack_webhook_url",
            "discord_webhook_url",
            "action_webhook_secret",
            "wazuh_url",
            "wazuh_user",
            "wazuh_password",
            "wazuh_command",
            "wazuh_agents",
            "public_url",
        ):
            raw = _env(field.upper())
            if raw:
                v[field] = raw
        if _env("PORT"):
            v["port"] = int(_env("PORT"))
        if _env("MAX_ISOLATIONS_PER_HOUR"):
            v["max_isolations_per_hour"] = int(_env("MAX_ISOLATIONS_PER_HOUR"))
        if _env("DATA_DIR"):
            v["data_dir"] = Path(_env("DATA_DIR"))
        if _env("ACTIONS"):
            v["actions"] = [a.strip() for a in _env("ACTIONS").split(",") if a.strip()]
        if _env("PROTECTED_NETWORKS"):
            v["protected_networks"] = ["127.0.0.0/8", "::1/128"] + [
                a.strip() for a in _env("PROTECTED_NETWORKS").split(",") if a.strip()
            ]
        if _env("ALERTS_ONLY_NETWORKS"):
            v["alerts_only_networks"] = [a.strip() for a in _env("ALERTS_ONLY_NETWORKS").split(",") if a.strip()]
        if _env("WAZUH_VERIFY_TLS"):
            v["wazuh_verify_tls"] = _env("WAZUH_VERIFY_TLS").lower() in {"1", "true", "yes"}
        return cls.model_validate(v)
