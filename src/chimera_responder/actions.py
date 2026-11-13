"""Containment actions. All free / open-source integrations.

* ``blocklist`` - maintains a plain-text IP blocklist served at
  ``/feeds/blocklist.txt``. pfSense/OPNsense URL aliases, FortiGate external
  threat feeds, nginx, fail2ban and most firewalls can consume it directly.
* ``webhook``   - signed JSON to any SOAR (Shuffle, n8n, Tines community...).
* ``wazuh``     - Wazuh 4.x API active response (free, open-source SIEM/XDR).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any

import anyio.to_thread
import httpx
from pydantic import BaseModel

from chimera.egress import EgressGuard
from chimera.signing import sign
from chimera_responder.config import ResponderSettings

log = logging.getLogger("chimera.responder.actions")


def wazuh_timeout(command: str) -> int:
    """Seconds after which Wazuh lifts a block, from a manager command name like ``firewall-drop3600``.

    Wazuh names each timed ``<active-response>`` ``<command><timeout>`` (see the agent's
    ``shared/ar.conf``). A ``!script`` command bypasses that config and never expires (0).
    """
    if command.startswith("!"):
        return 0
    digits = re.search(r"(\d+)$", command)
    return int(digits.group(1)) if digits else 0


def blocklist_entry(ip: str) -> str:
    """The feed entry for an address. IPv6 attackers get a whole /64 (one subscriber's
    allocation), because blocking a single address is defeated by rotating within it."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _wazuh_failure(item: dict[str, Any]) -> str:
    ids = ", ".join(map(str, item.get("id", [])))[:60]
    error = item.get("error")
    message = str(error.get("message", "?")) if isinstance(error, dict) else "?"
    return f"{ids}: {message[:80]}"


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
            out.append(self._wazuh_release(ip))
        return out

    def _wazuh_release(self, ip: str) -> ActionResult:
        """The Wazuh API cannot undo an active response; only the agent's own timeout can.

        A manager-defined command such as ``firewall-drop3600`` (an ``<active-response>``
        block with ``<timeout>3600</timeout>``) is removed by each agent when the timeout
        ends. A bare script (``!firewall-drop``) never expires, so say so plainly.
        """
        timeout = wazuh_timeout(self.s.wazuh_command)
        if timeout:
            return ActionResult(
                name="wazuh", ok=True, detail=f"Wazuh agents lift the block on {ip} automatically ({timeout}s timeout)"
            )
        return ActionResult(
            name="wazuh",
            ok=False,
            detail=(
                f"{self.s.wazuh_command} has no timeout, so the block on {ip} stays until removed on each agent "
                f"(e.g. iptables -D INPUT -s {ip} -j DROP). Use a timed command such as firewall-drop3600."
            ),
        )

    async def notify(self, text: str, title: str = "Chimera", urgent: bool = False, link: str = "") -> None:
        """Best-effort analyst notification to Slack / Discord webhooks and ntfy phone push."""
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
            if self.s.ntfy_url:
                plain = text.replace("*", "").replace("`", "")
                headers = {
                    # Header values must be latin-1; attacker text never reaches them.
                    "Title": title.encode("ascii", "replace").decode(),
                    "Priority": "urgent" if urgent else "default",
                    "Tags": "rotating_light" if urgent else "shield",
                }
                if link:
                    headers["Click"] = link
                try:
                    await client.post(self.s.ntfy_url, content=plain.encode()[:4000], headers=headers)
                except (httpx.HTTPError, PermissionError) as exc:
                    log.warning("ntfy notification failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    async def _blocklist(self, ip: str, add: bool) -> ActionResult:
        entry = blocklist_entry(ip)

        def edit() -> None:
            lines = {ln.strip() for ln in self.blocklist_path.read_text().splitlines() if ln.strip()}
            if add:
                lines.add(entry)
            else:
                lines.discard(entry)
                lines.discard(ip)  # entries written before /64 aggregation
            tmp = self.blocklist_path.with_suffix(".tmp")
            tmp.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
            tmp.replace(self.blocklist_path)

        await anyio.to_thread.run_sync(edit)
        return ActionResult(
            name="blocklist",
            ok=True,
            detail=f"{'added' if add else 'removed'} {entry} {'to' if add else 'from'} blocklist feed",
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
        affected = 0
        try:
            data = resp.json().get("data", {}) or {}
        except ValueError:
            data = {}
        if isinstance(data, dict):
            affected = int(data.get("total_affected_items") or 0)
            ids = [i for i in data.get("affected_items", []) if isinstance(i, str)][:20]
            detail += f", agents affected: {affected}" + (f" ({', '.join(ids)})" if ids else "")
            failed = data.get("failed_items") or []
            if failed:
                reasons = sorted({_wazuh_failure(f) for f in failed[:5] if isinstance(f, dict)})
                detail += f", failed: {data.get('total_failed_items', len(failed))} ({'; '.join(reasons)})"
        timeout = wazuh_timeout(self.s.wazuh_command)
        detail += f", auto-release after {timeout}s" if timeout else ", permanent until removed on the agents"
        # HTTP 200 with zero affected agents means nothing was blocked: never report that as isolation.
        return ActionResult(name="wazuh", ok=resp.is_success and affected > 0, detail=detail[:500])
