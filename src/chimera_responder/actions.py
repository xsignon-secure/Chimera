"""Containment actions. All free / open-source integrations.

* ``blocklist`` - maintains a plain-text IP blocklist served at
  ``/feeds/blocklist.txt``. pfSense/OPNsense URL aliases, FortiGate external
  threat feeds, nginx, fail2ban and most firewalls can consume it directly.
* ``webhook``   - signed JSON to any SOAR (Shuffle, n8n, Tines community...).
* ``wazuh``     - Wazuh 4.x API active response (free, open-source SIEM/XDR).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import anyio.to_thread
import httpx
from pydantic import BaseModel

from chimera.egress import EgressGuard
from chimera.signing import sign
from chimera_responder.config import ResponderSettings

log = logging.getLogger("chimera.responder.actions")


class ActionResult(BaseModel):
    name: str
    ok: bool
    detail: str


class Actions:
    def __init__(self, settings: ResponderSettings) -> None:
        self.s = settings
        self.guard = EgressGuard(settings.egress_hosts)
        self.blocklist_path: Path = settings.data_dir / "blocklist.txt"
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        self.blocklist_path.touch(exist_ok=True)

    async def isolate(self, ip: str, incident_id: str, context: dict[str, Any]) -> list[ActionResult]:
        out: list[ActionResult] = []
        for name in self.s.actions:
            try:
                if name == "blocklist":
                    out.append(await self._blocklist(ip, add=True))
                elif name == "webhook":
                    out.append(await self._webhook("isolate", ip, incident_id, context))
                elif name == "wazuh":
                    out.append(await self._wazuh(ip, incident_id))
            except Exception as exc:  # noqa: BLE001 - one failing integration must not block the others
                log.exception("action %s failed", name)
                out.append(ActionResult(name=name, ok=False, detail=f"{type(exc).__name__}: {exc}"[:300]))
        return out

    async def release(self, ip: str, incident_id: str) -> list[ActionResult]:
        out = [await self._blocklist(ip, add=False)] if "blocklist" in self.s.actions else []
        if "webhook" in self.s.actions:
            try:
                out.append(await self._webhook("release", ip, incident_id, {}))
            except httpx.HTTPError as exc:
                out.append(ActionResult(name="webhook", ok=False, detail=str(exc)[:300]))
        if "wazuh" in self.s.actions:
            out.append(
                ActionResult(
                    name="wazuh", ok=True, detail="Wazuh firewall-drop entries expire by their configured timeout"
                )
            )
        return out

    async def notify(self, text: str) -> None:
        """Best-effort analyst notification to Slack / Discord incoming webhooks."""
        targets = [
            (self.s.slack_webhook_url, {"text": text}),
            (
                self.s.discord_webhook_url,
                {"content": text.replace("*", "**")[:1900], "allowed_mentions": {"parse": []}},
            ),
        ]
        async with self.guard.client(timeout=5.0) as client:
            for url, payload in targets:
                if not url:
                    continue
                try:
                    await client.post(url, json=payload)
                except (httpx.HTTPError, PermissionError) as exc:
                    log.warning("notification failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    async def _blocklist(self, ip: str, add: bool) -> ActionResult:
        def edit() -> None:
            lines = {ln.strip() for ln in self.blocklist_path.read_text().splitlines() if ln.strip()}
            if add:
                lines.add(ip)
            else:
                lines.discard(ip)
            tmp = self.blocklist_path.with_suffix(".tmp")
            tmp.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
            tmp.replace(self.blocklist_path)

        await anyio.to_thread.run_sync(edit)
        return ActionResult(
            name="blocklist",
            ok=True,
            detail=f"{'added' if add else 'removed'} {ip} {'to' if add else 'from'} blocklist feed",
        )

    async def _webhook(self, action: str, ip: str, incident_id: str, context: dict[str, Any]) -> ActionResult:
        if not self.s.action_webhook_url:
            return ActionResult(name="webhook", ok=False, detail="RESPONDER_ACTION_WEBHOOK_URL not set")
        body = json.dumps(
            {
                "action": action,
                "target_ip": ip,
                "incident_id": incident_id,
                "source": "project-chimera",
                "context": context,
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        if self.s.action_webhook_secret:
            headers.update(sign(self.s.action_webhook_secret, body))
        async with self.guard.client(timeout=8.0) as client:
            resp = await client.post(self.s.action_webhook_url, content=body, headers=headers)
        return ActionResult(name="webhook", ok=resp.is_success, detail=f"SOAR webhook HTTP {resp.status_code}")

    async def _wazuh(self, ip: str, incident_id: str) -> ActionResult:
        if not (self.s.wazuh_url and self.s.wazuh_user and self.s.wazuh_password):
            return ActionResult(name="wazuh", ok=False, detail="Wazuh API URL/credentials not configured")
        base = self.s.wazuh_url.rstrip("/")
        async with self.guard.client(timeout=10.0, verify=self.s.wazuh_verify_tls) as client:
            auth = await client.post(
                f"{base}/security/user/authenticate", auth=(self.s.wazuh_user, self.s.wazuh_password)
            )
            auth.raise_for_status()
            token = auth.json()["data"]["token"]
            headers = {"Authorization": f"Bearer {token}"}
            agents = self.s.wazuh_agents
            params: dict[str, str] = {} if agents == "all" else {"agents_list": agents}
            body = {
                "command": self.s.wazuh_command,
                "arguments": [],
                "alert": {"data": {"srcip": ip, "chimera_incident": incident_id}},
            }
            resp = await client.put(f"{base}/active-response", params=params, json=body, headers=headers)
        detail = f"Wazuh active-response {self.s.wazuh_command} for {ip}: HTTP {resp.status_code}"
        if resp.is_success:
            affected = resp.json().get("data", {}).get("total_affected_items")
            detail += f", agents affected: {affected}"
        return ActionResult(name="wazuh", ok=resp.is_success, detail=detail)
