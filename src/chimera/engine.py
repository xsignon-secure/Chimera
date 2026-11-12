"""The engine wires settings, storage, deception and telemetry together, and
implements the sensor that observes every MCP message."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import time
from collections import defaultdict, deque
from contextvars import ContextVar
from typing import Any

import anyio

from chimera import __version__
from chimera.canary import CanaryHit, CanaryWatermarker
from chimera.config import Settings
from chimera.detect import (
    RECON_ATTACK,
    extract_indicators,
    fingerprint,
    flatten,
    looks_like_prose,
    max_severity,
)
from chimera.fakeworld import FakeWorld
from chimera.models import AgentFingerprint, Event, utcnow
from chimera.persona import PersonaLLM, persona_for
from chimera.profiles import Profile, get_profile
from chimera.scope import RequestScope, reset_scope, set_scope
from chimera.store import Store
from chimera.telemetry import Telemetry
from chimera.tools import REGISTRY, load

log = logging.getLogger("chimera")

# Populated by the ASGI layer for HTTP transports (trusted-proxy aware).
CLIENT_ADDR: ContextVar[tuple[str, int | None] | None] = ContextVar("chimera_client_addr", default=None)


class Engine:
    def __init__(self, settings: Settings, store: Store | None = None) -> None:
        self.settings = settings
        self.profile: Profile = get_profile(settings.profile)
        self.store = store or Store(settings.db_path)
        self.world = FakeWorld(settings.seed)
        self.canaries = CanaryWatermarker(
            self.store, settings.canary_secret, settings.public_base_url, settings.canarytokens_file
        )
        self.telemetry = Telemetry(settings, self.store, __version__)
        self.persona_llm = PersonaLLM(settings.persona_llm_url, settings.persona_llm_model, self.telemetry.guard)
        load()
        names = self.profile.tools or sorted(REGISTRY)
        self.tools = {n: REGISTRY[n] for n in names}
        self.server_name = settings.server_name or self.profile.server_name
        self.server_version = settings.server_version or self.profile.version
        # "Think time" between our last response and the caller's next request. Our own
        # injected latency is excluded, so pacing reflects the caller (LLM vs script).
        self._think: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._last_response: dict[str, float] = {}
        self._prose_seen: set[str] = set()
        self._fingerprints: dict[str, AgentFingerprint] = {}
        self._session_meta: dict[str, dict[str, Any]] = {}
        self._rng = random.Random()  # jitter only; not security sensitive

    async def start(self) -> None:
        await self.telemetry.prune()
        await self.canaries.warm()
        await self.telemetry.start()

    async def stop(self) -> None:
        await self.telemetry.stop()

    # ------------------------------------------------------------------ identity
    def session_key(self, ip: str, headers: dict[str, str], meta: dict[str, Any] | None = None) -> str:
        """Stable attacker-session id, derived from source IP + User-Agent.

        Works identically for the stateless 2026 protocol (no session header)
        and legacy stateful clients (whose ``initialize`` arrives before the
        server has assigned ``mcp-session-id``).
        """
        material = f"{ip}|{headers.get('user-agent', '')}"
        return "s_" + hashlib.sha256(material.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------ sensor
    async def sensor(self, ctx: Any, call_next: Any) -> Any:
        """MCP ServerMiddleware: observes every request and notification."""
        method: str = ctx.method
        params: dict[str, Any] = dict(ctx.params or {})
        meta: dict[str, Any] = dict(params.get("_meta") or {})
        req = getattr(ctx, "request", None)
        headers = {k.lower(): v for k, v in dict(getattr(req, "headers", {}) or {}).items()}
        addr = CLIENT_ADDR.get()
        if addr is None:
            client = getattr(req, "client", None)
            addr = (
                getattr(client, "host", None) or ("stdio" if req is None else "unknown"),
                getattr(client, "port", None),
            )
        ip, port = addr
        transport = "stdio" if req is None else "streamable-http"

        # Legacy handshake carries clientInfo in params; modern carries it in _meta.
        if method == "initialize":
            meta.setdefault("io.modelcontextprotocol/clientInfo", params.get("clientInfo") or {})
            meta.setdefault("io.modelcontextprotocol/clientCapabilities", params.get("capabilities") or {})
            meta.setdefault("io.modelcontextprotocol/protocolVersion", params.get("protocolVersion"))
        session_id = self.session_key(ip, headers, meta)
        sm = self._session_meta.setdefault(session_id, {})
        for k in (
            "io.modelcontextprotocol/clientInfo",
            "io.modelcontextprotocol/clientCapabilities",
            "io.modelcontextprotocol/protocolVersion",
        ):
            if meta.get(k):
                sm[k] = meta[k]

        self._bound_memory()
        now = utcnow()
        await self.store.touch_session(session_id, ip, now)
        arrived = time.monotonic()
        if session_id in self._last_response and not method.startswith("notifications/"):
            self._think[session_id].append(arrived - self._last_response[session_id])

        if method.startswith("notifications/"):
            return await call_next(ctx)

        raw_name = params.get("name") if method == "tools/call" else None
        tool_name = _clip(raw_name, 128) if raw_name is not None else None
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else None
        state = await self.store.load_state(session_id)
        state["_tool"] = tool_name or ""
        persona = persona_for(session_id)
        scope = RequestScope(engine=self, session_id=session_id, source_ip=ip, state=state, persona=persona)

        # Did a previously issued canary come back?
        inbound_text = flatten(arguments) if arguments else ""
        reused = _attribute(self.canaries.hits(inbound_text), session_id)

        token = set_scope(scope)
        outcome: str = "success"
        result: Any = None
        error: BaseException | None = None
        try:
            if method == "tools/call":
                lo, hi = self.settings.latency_min_ms, self.settings.latency_max_ms
                await anyio.sleep(self._rng.uniform(lo, max(lo, hi)) / 1000)
            result = await call_next(ctx)
        except BaseException as exc:  # recorded, then re-raised to the SDK
            error = exc
            outcome = "failure"
        finally:
            reset_scope(token)

        if scope.tool_failed or _is_error(result):
            outcome = "failure"

        self._last_response[session_id] = time.monotonic()
        if looks_like_prose(arguments):
            self._prose_seen.add(session_id)
        fp = fingerprint(
            sm.get("io.modelcontextprotocol/clientInfo"),
            sm.get("io.modelcontextprotocol/protocolVersion") or getattr(ctx, "protocol_version", None),
            headers.get("user-agent"),
            sm.get("io.modelcontextprotocol/clientCapabilities"),
            list(self._think[session_id]),
            session_id in self._prose_seen,
        )
        if self._fingerprints.get(session_id) != fp:
            self._fingerprints[session_id] = fp
            await self.store.save_fingerprint(session_id, fp)

        state.pop("_tool", None)
        await self.store.save_state(session_id, state)

        indicators = extract_indicators(
            inbound_text,
            scope.extra_urls,
            ignore_hosts=[self.world.domain, _host(self.settings.public_base_url)],
        )
        honey = self.tools.get(tool_name or "")
        if method == "tools/call":
            kind = "mcp.tool_call" if honey else "mcp.error"
            attack = list(honey.attack) if honey else []
            atlas = list(honey.atlas) if honey else []
            severity = honey.severity if honey else "medium"
            if outcome == "failure" and honey:
                severity = max_severity("medium", "high" if honey.severity == "critical" else "medium")
        else:
            kind = "mcp.request" if error is None else "mcp.error"
            attack = list(RECON_ATTACK.get(method, []))
            atlas = []
            severity = "low" if method in RECON_ATTACK else "info"
        if indicators.prompt_injection_markers:
            atlas.append("AML.T0051")
            severity = max_severity(severity, "high")
        if reused:
            severity = max_severity(severity, "high")

        event = Event(
            kind=kind,  # type: ignore[arg-type]
            severity=severity,
            profile=self.profile.key,
            session_id=session_id,
            source_ip=ip,
            source_port=port,
            transport=transport,  # type: ignore[arg-type]
            method=_clip(method, 64),
            tool=tool_name,
            arguments=_bounded(arguments),
            raw_params_sha256=hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest(),
            outcome=outcome,  # type: ignore[arg-type]
            response_summary=_summarize(result, error),
            mitre_attack=sorted(set(attack)),
            mitre_atlas=sorted(set(atlas)),
            canary_ids=scope.canary_ids,
            fingerprint=fp,
            indicators=None if indicators.is_empty() else indicators,
            persona=persona if tool_name else None,
            message=_message(method, tool_name, ip, fp, outcome),
        )
        # Telemetry is recorded BEFORE the response returns to the attacker.
        await self.telemetry.emit(event)
        for cid in scope.canary_ids:
            await self.telemetry.emit(
                Event(
                    kind="canary.issued",
                    severity="info",
                    profile=self.profile.key,
                    session_id=session_id,
                    source_ip=ip,
                    tool=tool_name,
                    canary_ids=[cid],
                    message=f"canary {cid} issued via {tool_name}",
                )
            )
        if reused:
            await self._emit_reuse(reused, session_id, ip, tool_name)

        if error is not None:
            raise error
        return result

    def _bound_memory(self, limit: int = 20_000) -> None:
        """Per-session caches are attacker-influenced (IP + User-Agent); cap them."""
        if len(self._session_meta) > limit or len(self._think) > limit:
            self._session_meta.clear()
            self._think.clear()
            self._last_response.clear()
            self._prose_seen.clear()
            self._fingerprints.clear()

    async def _emit_reuse(self, hits: list[CanaryHit], session_id: str, ip: str, tool: str | None) -> None:
        for hit in hits:
            rec = await self.store.get_canary(hit.canary_id)
            origin = (
                f"issued to session {hit.session_id} ({rec.source_ip if rec else '?'}) by {rec.tool if rec else '?'}"
            )
            cross = hit.session_id != session_id
            await self.telemetry.emit(
                Event(
                    kind="canary.reused",
                    severity="critical" if cross else "high",
                    profile=self.profile.key,
                    session_id=session_id,
                    source_ip=ip,
                    tool=tool,
                    canary_ids=[hit.canary_id],
                    mitre_attack=["T1078"],
                    mitre_atlas=["AML.T0055"],
                    message=(
                        f"stolen {hit.kind} canary {hit.canary_id} presented back to honeypot"
                        f"{' from a DIFFERENT session (credential sharing / lateral movement)' if cross else ''}"
                        f"; {origin}"
                    ),
                )
            )

    async def canary_callback(self, path: str, ip: str, port: int | None, headers: dict[str, str]) -> bool:
        """Handle an HTTP hit on a URL canary. Returns True if it matched."""
        cid = self.canaries.callback_token_to_id(path)
        if not cid:
            return False
        rec = await self.store.get_canary(cid)
        sid = rec.session_id if rec else "unknown"
        # A link can be pasted anywhere: chat unfurl bots, mail scanners and colleagues fetch it
        # too. A hit from the IP that stole it is strong evidence; from anywhere else it is
        # context only (medium), so it can never on its own isolate an innocent fetcher.
        same_thief = rec is not None and rec.source_ip == ip
        await self.telemetry.emit(
            Event(
                kind="canary.triggered",
                severity="high" if same_thief else "medium",
                profile=self.profile.key,
                session_id=sid,
                source_ip=ip,
                source_port=port,
                transport="http",
                method="GET",
                canary_ids=[cid],
                mitre_attack=["T1078", "T1550"],
                mitre_atlas=["AML.T0055"],
                message=(
                    f"URL canary {cid} opened from {ip} (UA: {_clip(headers.get('user-agent', '-'), 80)})"
                    f"{'' if same_thief else ' - a different host than the thief (could be a link-preview bot)'}; "
                    f"originally issued to {rec.source_ip if rec else '?'} via {rec.tool if rec else '?'}"
                ),
            )
        )
        return True

    async def protocol_error(
        self, method: str, status: int, ip: str, port: int | None, headers: dict[str, str]
    ) -> None:
        await self.telemetry.emit(
            Event(
                kind="mcp.error",
                severity="low",
                profile=self.profile.key,
                session_id=self.session_key(ip, headers),
                source_ip=ip,
                source_port=port,
                method=method,
                outcome="failure",
                mitre_attack=["T1595.002"],
                message=f"malformed or rejected MCP request: {method} -> HTTP {status} "
                f"(UA: {headers.get('user-agent', '-')[:80]})",
            )
        )

    async def http_probe(self, path: str, method: str, ip: str, port: int | None, headers: dict[str, str]) -> None:
        await self.telemetry.emit(
            Event(
                kind="http.probe",
                severity="low",
                profile=self.profile.key,
                session_id=self.session_key(ip, headers, {}),
                source_ip=ip,
                source_port=port,
                transport="http",
                method=method,
                mitre_attack=["T1595.002"],
                message=f"{method} {path[:200]} (UA: {headers.get('user-agent', '-')[:80]})",
            )
        )


def _clip(value: object, limit: int = 256) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _attribute(hits: list[CanaryHit], session_id: str) -> list[CanaryHit]:
    """One hit per reused value, preferring the presenting session's own issuance.

    An external Canarytokens key can be handed to several sessions once the pool
    rotates; without this a session reusing its own key would be blamed on another.
    """
    chosen: dict[str, CanaryHit] = {}
    for h in hits:
        current_pick = chosen.get(h.marker)
        if current_pick is None or (h.session_id == session_id and current_pick.session_id != session_id):
            chosen[h.marker] = h
    return sorted(chosen.values(), key=lambda h: h.canary_id)


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def _is_error(result: Any) -> bool:
    if result is None:
        return False
    for attr in ("is_error", "isError"):
        if getattr(result, attr, False):
            return True
    if isinstance(result, dict):
        return bool(result.get("isError") or result.get("is_error"))
    return False


def _bounded(arguments: dict[str, Any] | None, per_value: int = 1024, total: int = 4096) -> dict[str, object] | None:
    """Keep evidence useful but bounded: an attacker must not be able to fill the disk."""
    if arguments is None:
        return None
    out: dict[str, object] = {}
    used = 0
    for k, v in list(arguments.items())[:32]:
        val: object = v if isinstance(v, int | float | bool) or v is None else str(v)
        if isinstance(val, str):
            budget = max(0, min(per_value, total - used))
            val = val if len(val) <= budget else val[:budget] + f"…[{len(str(v))} chars]"
            used += len(val)
        out[_clip(k, 64)] = val
        if used >= total:
            out["_truncated"] = True
            break
    return out


def _summarize(result: Any, error: BaseException | None) -> str | None:
    if error is not None:
        return f"{type(error).__name__}: {str(error)[:200]}"
    if result is None:
        return None
    try:
        text = result.model_dump_json() if hasattr(result, "model_dump_json") else json.dumps(result, default=str)
    except (TypeError, ValueError):
        text = str(result)
    return text[:500]


def _message(method: str, tool: str | None, ip: str, fp: AgentFingerprint, outcome: str) -> str:
    who = fp.client_name or "unidentified client"
    if tool:
        return f"{who} at {ip} called honey tool {tool} ({outcome}); classified {fp.classification}"
    return f"{who} at {ip} sent {method}"
