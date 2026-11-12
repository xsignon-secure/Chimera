"""SQLite persistence for events, sessions and issued canaries.

SQLite keeps the deployment free and dependency-light while surviving
restarts. All blocking calls run in a worker thread so the event loop never
stalls on disk I/O.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import anyio.to_thread

from chimera.config import SEVERITY_RANK
from chimera.models import AgentFingerprint, CanaryRecord, Event, SessionSummary

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    tool TEXT,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS canaries (
    canary_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    tool TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    external INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT
);
"""


class Store:
    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- low level ---------------------------------------------------------
    def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return list(cur.fetchall())

    async def _run(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return await anyio.to_thread.run_sync(self._exec, sql, params)

    # -- events ------------------------------------------------------------
    async def add_event(self, event: Event) -> None:
        await self._run(
            "INSERT OR REPLACE INTO events(id, ts, session_id, source_ip, kind, severity, tool, body)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                event.id,
                event.timestamp.isoformat(),
                event.session_id,
                event.source_ip,
                event.kind,
                event.severity,
                event.tool,
                event.model_dump_json(),
            ),
        )

    async def events_for_session(self, session_id: str) -> list[Event]:
        rows = await self._run("SELECT body FROM events WHERE session_id=? ORDER BY ts", (session_id,))
        return [Event.model_validate_json(r[0]) for r in rows]

    async def recent_events(self, limit: int = 100) -> list[Event]:
        rows = await self._run("SELECT body FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        return [Event.model_validate_json(r[0]) for r in rows]

    # -- sessions ----------------------------------------------------------
    async def touch_session(self, session_id: str, source_ip: str, now: datetime) -> None:
        await self._run(
            "INSERT INTO sessions(session_id, source_ip, first_seen, last_seen) VALUES (?,?,?,?)"
            " ON CONFLICT(session_id) DO UPDATE SET last_seen=excluded.last_seen",
            (session_id, source_ip, now.isoformat(), now.isoformat()),
        )

    async def save_fingerprint(self, session_id: str, fp: AgentFingerprint) -> None:
        await self._run("UPDATE sessions SET fingerprint=? WHERE session_id=?", (fp.model_dump_json(), session_id))

    async def load_state(self, session_id: str) -> dict[str, Any]:
        rows = await self._run("SELECT state FROM sessions WHERE session_id=?", (session_id,))
        if not rows:
            return {}
        loaded: dict[str, Any] = json.loads(rows[0][0])
        return loaded

    async def save_state(self, session_id: str, state: dict[str, Any]) -> None:
        await self._run("UPDATE sessions SET state=? WHERE session_id=?", (json.dumps(state), session_id))

    async def list_sessions(self, limit: int = 50) -> list[SessionSummary]:
        rows = await self._run(
            "SELECT session_id, source_ip, first_seen, last_seen, fingerprint FROM sessions"
            " ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        out: list[SessionSummary] = []
        for sid, ip, first, last, fp in rows:
            stats = await self._run(
                "SELECT COUNT(*), GROUP_CONCAT(DISTINCT severity) FROM events WHERE session_id=?", (sid,)
            )
            tools = await self._run(
                "SELECT tool FROM events WHERE session_id=? AND kind='mcp.tool_call' ORDER BY ts", (sid,)
            )
            sevs = (stats[0][1] or "info").split(",")
            out.append(
                SessionSummary(
                    session_id=sid,
                    source_ip=ip,
                    first_seen=datetime.fromisoformat(first),
                    last_seen=datetime.fromisoformat(last),
                    request_count=int(stats[0][0]),
                    tool_calls=[t[0] for t in tools if t[0]],
                    max_severity=max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0)),  # type: ignore[arg-type]
                    fingerprint=AgentFingerprint.model_validate_json(fp) if fp else None,
                )
            )
        return out

    # -- canaries ----------------------------------------------------------
    async def add_canary(self, rec: CanaryRecord) -> None:
        await self._run(
            "INSERT OR REPLACE INTO canaries(canary_id, kind, value, session_id, source_ip, tool, issued_at,"
            " external) VALUES (?,?,?,?,?,?,?,?)",
            (
                rec.canary_id,
                rec.kind,
                rec.value,
                rec.session_id,
                rec.source_ip,
                rec.tool,
                rec.issued_at.isoformat(),
                int(rec.external),
            ),
        )

    async def get_canary(self, canary_id: str) -> CanaryRecord | None:
        rows = await self._run(
            "SELECT canary_id, kind, value, session_id, source_ip, tool, issued_at, external"
            " FROM canaries WHERE canary_id=?",
            (canary_id,),
        )
        return _canary(rows[0]) if rows else None

    async def all_canaries(self) -> list[CanaryRecord]:
        rows = await self._run(
            "SELECT canary_id, kind, value, session_id, source_ip, tool, issued_at, external FROM canaries"
        )
        return [_canary(r) for r in rows]

    async def external_values_in_use(self) -> set[str]:
        rows = await self._run("SELECT value FROM canaries WHERE external=1")
        return {r[0] for r in rows}


def _canary(row: sqlite3.Row | tuple[Any, ...]) -> CanaryRecord:
    cid, kind, value, sid, ip, tool, issued, ext = row
    return CanaryRecord(
        canary_id=cid,
        kind=kind,
        value=value,
        session_id=sid,
        source_ip=ip,
        tool=tool,
        issued_at=datetime.fromisoformat(issued),
        external=bool(ext),
    )
