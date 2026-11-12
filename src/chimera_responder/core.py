"""Incident correlation and containment policy.

One incident per attacking source IP. Honeypot alerts are folded into it, and
once its severity reaches the trigger level an isolation request is created.
What happens next depends on the mode:

* ``dry_run``  - the plan is recorded and shown, nothing is executed.
* ``approve``  - (default) the request waits for one analyst click or an
  ``approve_isolation`` call from a Blue Team agent.
* ``auto``     - containment runs immediately.

Safety rails apply in every mode: protected networks are never isolated, a
per-hour cap stops a flood of spoofed alerts from mass-isolating the network,
and every decision is written to an append-only audit log.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import anyio.to_thread
from pydantic import BaseModel, Field

from chimera.config import SEVERITY_RANK
from chimera.models import Event
from chimera_responder.actions import ActionResult, Actions
from chimera_responder.config import ResponderSettings

Status = Literal[
    "monitoring", "pending_approval", "dry_run", "isolated", "rejected", "released", "failed", "blocked_by_policy"
]


class Incident(BaseModel):
    id: str
    source_ip: str
    status: Status = "monitoring"
    severity: str = "info"
    created: datetime
    updated: datetime
    event_count: int = 0
    sessions: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    canaries: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    clients: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    approval_nonce: str = Field(default_factory=lambda: secrets.token_urlsafe(16))


def _now() -> datetime:
    return datetime.now(UTC)


class IncidentStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, source_ip TEXT UNIQUE, updated TEXT,"
            " body TEXT);"
            "CREATE TABLE IF NOT EXISTS audit (ts TEXT, incident TEXT, actor TEXT, action TEXT, detail TEXT);"
            "CREATE TABLE IF NOT EXISTS seen (event_id TEXT PRIMARY KEY);"
        )

    def _q(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with self._lock:
            return list(self._db.execute(sql, params).fetchall())

    async def q(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        return await anyio.to_thread.run_sync(self._q, sql, params)

    async def get_by_ip(self, ip: str) -> Incident | None:
        rows = await self.q("SELECT body FROM incidents WHERE source_ip=?", (ip,))
        return Incident.model_validate_json(rows[0][0]) if rows else None

    async def get(self, incident_id: str) -> Incident | None:
        rows = await self.q("SELECT body FROM incidents WHERE id=?", (incident_id,))
        return Incident.model_validate_json(rows[0][0]) if rows else None

    async def save(self, inc: Incident) -> None:
        await self.q(
            "INSERT INTO incidents(id, source_ip, updated, body) VALUES (?,?,?,?) ON CONFLICT(id) DO"
            " UPDATE SET updated=excluded.updated, body=excluded.body",
            (inc.id, inc.source_ip, inc.updated.isoformat(), inc.model_dump_json()),
        )

    async def all(self, limit: int = 100) -> list[Incident]:
        rows = await self.q("SELECT body FROM incidents ORDER BY updated DESC LIMIT ?", (limit,))
        return [Incident.model_validate_json(r[0]) for r in rows]

    async def first_seen(self, event_id: str) -> bool:
        rows = await self.q("INSERT OR IGNORE INTO seen(event_id) VALUES (?) RETURNING event_id", (event_id,))
        return bool(rows)

    async def audit(self, incident: str, actor: str, action: str, detail: str = "") -> None:
        await self.q("INSERT INTO audit VALUES (?,?,?,?,?)", (_now().isoformat(), incident, actor, action, detail))

    async def audit_log(self, limit: int = 200) -> list[dict[str, str]]:
        rows = await self.q("SELECT ts, incident, actor, action, detail FROM audit ORDER BY ts DESC LIMIT ?", (limit,))
        return [dict(zip(("ts", "incident", "actor", "action", "detail"), r, strict=True)) for r in rows]

    async def isolated_ips(self) -> list[str]:
        return [i.source_ip for i in await self.all(10_000) if i.status == "isolated"]


class Responder:
    def __init__(
        self, settings: ResponderSettings, store: IncidentStore | None = None, actions: Actions | None = None
    ) -> None:
        self.settings = settings
        self.store = store or IncidentStore(settings.data_dir / "responder.db")
        self.actions = actions or Actions(settings)
        self._protected = [ipaddress.ip_network(c, strict=False) for c in settings.protected_networks]
        self._recent_isolations: list[float] = []
        self._lock = anyio.Lock()

    def is_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # never act on something that is not an IP
        return any(addr in n for n in self._protected)

    async def ingest(self, event: Event) -> Incident | None:
        if not event.source_ip or event.source_ip in {"stdio", "unknown"}:
            return None
        if not await self.store.first_seen(event.id):
            return await self.store.get_by_ip(event.source_ip)  # duplicate delivery
        async with self._lock:
            inc = await self.store.get_by_ip(event.source_ip)
            if inc is None:
                inc = Incident(
                    id="INC-" + secrets.token_hex(4).upper(),
                    source_ip=event.source_ip,
                    created=event.timestamp,
                    updated=_now(),
                )
                await self.store.audit(inc.id, "system", "opened", f"first alert {event.kind} from {inc.source_ip}")
            before = inc.status
            _fold(inc, event)
            await self._evaluate(inc)
            await self.store.save(inc)
        if inc.status != before:
            await self._notify(inc)
        return inc

    async def _evaluate(self, inc: Incident) -> None:
        if SEVERITY_RANK.get(inc.severity, 0) < SEVERITY_RANK[self.settings.trigger_severity]:
            return
        if inc.status not in {"monitoring"}:
            return
        if self.is_protected(inc.source_ip):
            inc.status = "blocked_by_policy"
            await self.store.audit(inc.id, "policy", "refused", f"{inc.source_ip} is in a protected network")
            return
        mode = self.settings.mode
        if mode == "dry_run":
            inc.status = "dry_run"
            plan = ", ".join(self.settings.actions)
            inc.actions.append(
                {
                    "ts": _now().isoformat(),
                    "action": "plan",
                    "ok": True,
                    "detail": f"DRY RUN: would isolate {inc.source_ip} via {plan}",
                }
            )
            await self.store.audit(inc.id, "system", "dry_run", f"would isolate via {plan}")
        elif mode == "approve":
            inc.status = "pending_approval"
            await self.store.audit(inc.id, "system", "approval_requested", inc.source_ip)
        else:
            await self._isolate(inc, actor="auto")

    async def _isolate(self, inc: Incident, actor: str) -> None:
        now = time.time()
        self._recent_isolations = [t for t in self._recent_isolations if now - t < 3600]
        if len(self._recent_isolations) >= self.settings.max_isolations_per_hour:
            inc.status = "pending_approval"
            await self.store.audit(
                inc.id,
                "policy",
                "rate_capped",
                f"hourly cap {self.settings.max_isolations_per_hour} reached; needs approval",
            )
            return
        self._recent_isolations.append(now)
        results: list[ActionResult] = await self.actions.isolate(inc.source_ip, inc.id, _context(inc))
        for r in results:
            inc.actions.append({"ts": _now().isoformat(), "action": r.name, "ok": r.ok, "detail": r.detail})
        inc.status = "isolated" if any(r.ok for r in results) else "failed"
        inc.updated = _now()
        await self.store.audit(
            inc.id, actor, "isolate", "; ".join(f"{r.name}:{'ok' if r.ok else 'fail'}" for r in results)
        )

    async def _notify(self, inc: Incident) -> None:
        if not (self.settings.slack_webhook_url or self.settings.discord_webhook_url):
            return
        verb = {
            "pending_approval": "needs your approval to isolate",
            "isolated": "was isolated",
            "dry_run": "would be isolated (dry run)",
            "failed": "isolation FAILED",
            "blocked_by_policy": "is protected; isolation refused",
        }.get(inc.status, inc.status)
        text = (
            f"*[{inc.severity.upper()}] MCP honeypot incident {inc.id}*: `{inc.source_ip}` {verb}.\n"
            f"Tools: {', '.join(inc.tools[:5]) or '-'} | Client: {', '.join(inc.clients[:2]) or '-'}\n"
            f"{self.settings.public_url.rstrip('/')}/incidents/{inc.id}"
        )
        await self.actions.notify(text)

    async def approve(self, incident_id: str, actor: str, nonce: str | None = None) -> Incident:
        async with self._lock:
            inc = await self.store.get(incident_id)
            if inc is None:
                raise KeyError(incident_id)
            if nonce is not None and not secrets.compare_digest(nonce, inc.approval_nonce):
                raise PermissionError("stale or invalid approval token")
            if inc.status not in {"pending_approval", "dry_run", "monitoring", "failed", "released"}:
                raise ValueError(f"cannot isolate an incident in state {inc.status}")
            if self.is_protected(inc.source_ip):
                raise PermissionError(f"{inc.source_ip} is protected and will not be isolated")
            await self._isolate(inc, actor=actor)
            inc.approval_nonce = secrets.token_urlsafe(16)
            await self.store.save(inc)
        await self._notify(inc)
        return inc

    async def reject(self, incident_id: str, actor: str, reason: str = "") -> Incident:
        async with self._lock:
            inc = await self.store.get(incident_id)
            if inc is None:
                raise KeyError(incident_id)
            inc.status = "rejected"
            inc.updated = _now()
            await self.store.audit(inc.id, actor, "rejected", reason[:500])
            await self.store.save(inc)
            return inc

    async def release(self, incident_id: str, actor: str) -> Incident:
        async with self._lock:
            inc = await self.store.get(incident_id)
            if inc is None:
                raise KeyError(incident_id)
            results = await self.actions.release(inc.source_ip, inc.id)
            for r in results:
                inc.actions.append(
                    {"ts": _now().isoformat(), "action": "release:" + r.name, "ok": r.ok, "detail": r.detail}
                )
            inc.status = "released"
            inc.updated = _now()
            await self.store.audit(inc.id, actor, "released", inc.source_ip)
            await self.store.save(inc)
            return inc


def _fold(inc: Incident, e: Event) -> None:
    inc.updated = _now()
    inc.event_count += 1
    if SEVERITY_RANK.get(e.severity, 0) > SEVERITY_RANK.get(inc.severity, 0):
        inc.severity = e.severity

    def add(lst: list[str], *vals: str | None) -> None:
        for v in vals:
            if v and v not in lst and len(lst) < 200:
                lst.append(v)

    add(inc.sessions, e.session_id)
    add(inc.tools, e.tool)
    add(inc.techniques, *e.mitre_attack, *e.mitre_atlas)
    add(inc.canaries, *e.canary_ids)
    if e.indicators:
        add(inc.iocs, *e.indicators.urls, *e.indicators.domains)
    if e.fingerprint and e.fingerprint.client_name:
        add(inc.clients, f"{e.fingerprint.client_name} ({e.fingerprint.classification})")
    inc.timeline.append(
        {
            "ts": e.timestamp.isoformat(),
            "kind": e.kind,
            "severity": e.severity,
            "tool": e.tool,
            "message": e.message[:300],
        }
    )
    inc.timeline = inc.timeline[-200:]


def _context(inc: Incident) -> dict[str, Any]:
    ctx: dict[str, Any] = json.loads(
        inc.model_dump_json(
            include={"id", "source_ip", "severity", "tools", "techniques", "canaries", "iocs", "clients", "sessions"}
        )
    )
    return ctx
