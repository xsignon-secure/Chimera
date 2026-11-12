"""Telemetry pipeline.

Every event is written locally (SQLite + JSONL + stdout) *before* the
honeypot answers the attacker. Events at or above ``alert_min_severity`` are
also pushed to remote sinks (signed webhook for the Blue Team responder,
Slack, Discord, CEF syslog) from a background queue, so a slow SIEM never
delays the response and never reveals the sensor through timing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import sys
from pathlib import Path
from typing import Any

import anyio.to_thread
import httpx

from chimera.config import SEVERITY_RANK, Settings
from chimera.egress import EgressGuard
from chimera.models import Event
from chimera.signing import sign
from chimera.store import Store

log = logging.getLogger("chimera.telemetry")

WEBHOOK_MAX_BYTES = 64 * 1024
JSONL_MAX_BYTES = 50 * 1024 * 1024
JSONL_KEEP = 5

_CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


def to_cef(event: Event, version: str) -> str:
    def esc(v: object) -> str:
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")

    def esc_h(v: object) -> str:
        return str(v).replace("\\", "\\\\").replace("|", "\\|")

    name = f"{event.kind} {event.tool or event.method or ''}".strip()
    ext = {
        "rt": int(event.timestamp.timestamp() * 1000),
        "src": event.source_ip,
        "cs1Label": "session",
        "cs1": event.session_id,
        "cs2Label": "mitre_attack",
        "cs2": ",".join(event.mitre_attack),
        "cs3Label": "mitre_atlas",
        "cs3": ",".join(event.mitre_atlas),
        "cs4Label": "canaries",
        "cs4": ",".join(event.canary_ids),
        "cs5Label": "client",
        "cs5": (event.fingerprint.client_name if event.fingerprint else "") or "",
        "act": event.outcome,
        "msg": event.message[:512],
    }
    ext_s = " ".join(f"{k}={esc(v)}" for k, v in ext.items() if v not in ("", None))
    return (
        f"CEF:0|ProjectChimera|MCP-Honeypot|{esc_h(version)}|{esc_h(event.kind)}|{esc_h(name)}|"
        f"{_CEF_SEV.get(event.severity, 5)}|{ext_s}"
    )


def chat_escape(value: object, limit: int = 200) -> str:
    """Neutralise attacker text for Slack mrkdwn / Discord: no links, mentions or formatting."""
    text = str(value)[:limit]
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("@", "@\u200b").replace("`", "'").replace("*", "").replace("_", " ").replace("~", "")
    return text.replace("\n", " ")


def chat_text(event: Event) -> str:
    fp = event.fingerprint
    who = f"{chat_escape(fp.client_name or 'unknown client', 80)} ({fp.classification})" if fp else "unknown client"
    lines = [
        f"*[{event.severity.upper()}] MCP honeypot: {event.kind}*",
        f"Source: `{event.source_ip}`  Session: `{event.session_id}`  Client: {who}",
    ]
    if event.tool:
        lines.append(f"Tool: `{chat_escape(event.tool, 80)}`  Outcome: {event.outcome}")
    if event.mitre_attack or event.mitre_atlas:
        lines.append("MITRE: " + ", ".join(event.mitre_attack + event.mitre_atlas))
    if event.canary_ids:
        lines.append("Canaries: " + ", ".join(event.canary_ids[:6]))
    if event.indicators and event.indicators.urls:
        lines.append(
            "IOCs (defanged): "
            + ", ".join(chat_escape(u.replace("://", "[:]//"), 120) for u in event.indicators.urls[:5])
        )
    if event.message:
        lines.append(chat_escape(event.message, 300))
    return "\n".join(lines)


class Telemetry:
    def __init__(self, settings: Settings, store: Store, version: str) -> None:
        self.settings = settings
        self.store = store
        self.version = version
        self.guard = EgressGuard(settings.egress_allowlist)
        self._queue: asyncio.Queue[Event] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._jsonl: Path = settings.events_path
        self._jsonl.parent.mkdir(parents=True, exist_ok=True)
        self._syslog: tuple[str, int] | None = None
        if settings.syslog_target:
            host, _, port = settings.syslog_target.rpartition(":")
            self._syslog = (host, int(port or 514))
        self.sent_ok = 0
        self.sent_failed = 0
        self._since_prune = 0

    async def prune(self) -> None:
        st = self.settings
        await self.store.prune(st.retention_days, st.max_events, st.canary_retention_days, st.max_canaries)

    @property
    def remote_enabled(self) -> bool:
        s = self.settings
        return bool(s.webhook_url or s.slack_webhook_url or s.discord_webhook_url or self._syslog)

    async def start(self) -> None:
        if self.remote_enabled and self._worker is None:
            self._queue = asyncio.Queue(maxsize=10_000)
            self._worker = asyncio.create_task(self._run(), name="chimera-telemetry")

    async def stop(self) -> None:
        if self._queue is not None and self._worker is not None:
            try:
                await asyncio.wait_for(self._queue.join(), timeout=5)
            except TimeoutError:
                pass
            self._worker.cancel()
            self._worker = None

    async def emit(self, event: Event) -> None:
        await self.store.add_event(event)
        self._since_prune += 1
        if self._since_prune >= 1000:
            self._since_prune = 0
            await self.prune()
        line = event.model_dump_json()
        await anyio.to_thread.run_sync(self._append, line)
        if self.settings.log_stdout:
            print(line, file=sys.stdout, flush=True)
        if self._queue is not None and SEVERITY_RANK[event.severity] >= SEVERITY_RANK[self.settings.alert_min_severity]:
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                log.warning("alert queue full; dropping remote alert %s", event.id)

    def _append(self, line: str) -> None:
        try:
            if self._jsonl.exists() and self._jsonl.stat().st_size > JSONL_MAX_BYTES:
                for i in range(JSONL_KEEP - 1, 0, -1):
                    older = self._jsonl.with_name(f"{self._jsonl.name}.{i}")
                    if older.exists():
                        older.replace(self._jsonl.with_name(f"{self._jsonl.name}.{i + 1}"))
                self._jsonl.replace(self._jsonl.with_name(f"{self._jsonl.name}.1"))
        except OSError:
            pass
        with self._jsonl.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    async def _run(self) -> None:
        assert self._queue is not None
        async with self.guard.client(timeout=5.0) as client:
            while True:
                event = await self._queue.get()
                try:
                    await self._dispatch(client, event)
                finally:
                    self._queue.task_done()

    async def _dispatch(self, client: httpx.AsyncClient, event: Event) -> None:
        s = self.settings
        body = event.model_dump_json().encode()
        if s.webhook_url:
            if len(body) > WEBHOOK_MAX_BYTES:
                body = event.compact().model_dump_json().encode()
            headers = {"Content-Type": "application/json", "User-Agent": f"chimera/{self.version}"}
            if s.webhook_secret:
                headers.update(sign(s.webhook_secret, body))
            status = await self._post(client, s.webhook_url, content=body, headers=headers)
            if status == 413:  # never silently drop a containment signal
                small = event.compact().model_dump_json().encode()
                headers = {"Content-Type": "application/json", "User-Agent": f"chimera/{self.version}"}
                if s.webhook_secret:
                    headers.update(sign(s.webhook_secret, small))
                await self._post(client, s.webhook_url, content=small, headers=headers)
        if s.slack_webhook_url:
            await self._post(client, s.slack_webhook_url, json={"text": chat_text(event)})
        if s.discord_webhook_url:
            await self._post(
                client,
                s.discord_webhook_url,
                json={"content": chat_text(event).replace("*", "**")[:1900], "allowed_mentions": {"parse": []}},
            )
        if self._syslog:
            msg = (
                f"<{_syslog_pri(event.severity)}>1 {event.timestamp.isoformat()} chimera chimera - - - "
                f"{to_cef(event, self.version)}"
            )
            await anyio.to_thread.run_sync(self._send_udp, msg.encode()[:8192])

    async def _post(self, client: httpx.AsyncClient, url: str, **kwargs: Any) -> int:
        """POST with retries on 5xx/network errors. Returns the final HTTP status (0 = no response)."""
        status = 0
        for attempt in range(3):
            try:
                resp = await client.post(url, **kwargs)
                status = resp.status_code
                if status < 500:
                    if status >= 400:
                        log.warning("alert sink %s rejected event: HTTP %s", httpx.URL(url).host, status)
                        self.sent_failed += 1
                    else:
                        self.sent_ok += 1
                    return status
            except PermissionError as exc:
                log.error("%s", exc)
                self.sent_failed += 1
                return 0
            except httpx.HTTPError as exc:
                log.warning("alert sink error (%s), attempt %d", type(exc).__name__, attempt + 1)
            await asyncio.sleep(0.5 * 2**attempt)
        self.sent_failed += 1
        return status

    def _send_udp(self, payload: bytes) -> None:
        assert self._syslog is not None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, self._syslog)


def _syslog_pri(severity: str) -> int:
    # facility local4 (20) * 8 + syslog severity
    sev = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}.get(severity, 5)
    return 20 * 8 + sev


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)
