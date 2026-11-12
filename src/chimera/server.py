"""Builds the MCP server and the network-facing ASGI application."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from chimera.config import Settings
from chimera.engine import CLIENT_ADDR, Engine

log = logging.getLogger("chimera.server")

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def build_mcp(engine: Engine) -> MCPServer:
    p = engine.profile
    server: MCPServer = MCPServer(
        name=p.server_name,
        version=p.version,
        instructions=p.instructions,
        middleware=[engine.sensor],
        log_level="WARNING",
    )
    for tool in engine.tools.values():
        server.add_tool(tool.fn, name=tool.name, description=tool.description, structured_output=False)
    return server


class ClientAddressMiddleware:
    """Resolves the real client address, trusting X-Forwarded-For only from configured proxies."""

    def __init__(self, app: ASGIApp, trusted: list[str]) -> None:
        self.app = app
        self.trusted = [ipaddress.ip_network(c, strict=False) for c in trusted]

    def resolve(self, scope: Scope) -> tuple[str, int | None]:
        peer = scope.get("client") or ("unknown", None)
        ip, port = str(peer[0]), peer[1]
        if not self.trusted:
            return ip, port
        try:
            if not any(ipaddress.ip_address(ip) in n for n in self.trusted):
                return ip, port
        except ValueError:
            return ip, port
        headers = {k.decode().lower(): v.decode(errors="replace") for k, v in scope.get("headers", [])}
        xff = headers.get("x-forwarded-for", "")
        # Walk right-to-left, skipping trusted hops: the first untrusted address is the client.
        for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
            try:
                addr = ipaddress.ip_address(hop)
            except ValueError:
                break
            if not any(addr in n for n in self.trusted):
                return str(addr), None
        real = headers.get("x-real-ip")
        return (real, None) if real else (ip, port)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        addr = self.resolve(scope)
        scope.setdefault("state", {})["chimera_addr"] = addr
        token = CLIENT_ADDR.set(addr)
        try:
            await self.app(scope, receive, send)
        finally:
            CLIENT_ADDR.reset(token)


class RateLimitMiddleware:
    """Per-IP sliding-window limit. Keeps the honeypot cheap to run and hard to DoS."""

    def __init__(self, app: ASGIApp, per_minute: int) -> None:
        self.app = app
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.per_minute <= 0:
            await self.app(scope, receive, send)
            return
        ip = (scope.get("state", {}).get("chimera_addr") or ("?",))[0]
        now = time.monotonic()
        q = self.hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            resp = PlainTextResponse("Too Many Requests", status_code=429, headers={"Retry-After": "30"})
            await resp(scope, receive, send)
            return
        q.append(now)
        if len(self.hits) > 50_000:  # bound memory under spoofed-source floods
            self.hits.clear()
        await self.app(scope, receive, send)


_LOGIN_PAGE = """<!doctype html><html><head><title>{name} | Sign in</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:80px auto">
<h2>{name}</h2><p>Sign in with your corporate SSO account to continue.</p>
<form method="post" action="/login"><input name="username" placeholder="username"><br><br>
<input name="password" type="password" placeholder="password"><br><br><button>Sign in</button></form>
</body></html>"""


class ChimeraApp:
    """Top-level ASGI app: MCP endpoint, canary callbacks, and decoy HTTP surface."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        s = engine.settings
        self.mcp = build_mcp(engine)
        self.mcp_app = self.mcp.streamable_http_app(
            streamable_http_path=s.mcp_path,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
            max_request_body_size=512 * 1024,
            max_sessions=2000,
            session_idle_timeout=1800,
            host=s.host,
        )
        inner: ASGIApp = self._dispatch
        self.app: ASGIApp = ClientAddressMiddleware(
            RateLimitMiddleware(inner, s.rate_limit_per_minute), s.trusted_proxies
        )

    @contextlib.asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        await self.engine.start()
        try:
            async with self.mcp_app.router.lifespan_context(self.mcp_app):
                yield
        finally:
            await self.engine.stop()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        await self.app(scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        cm = self.lifespan()
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                try:
                    await cm.__aenter__()
                except Exception as exc:  # noqa: BLE001
                    log.exception("startup failed")
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await cm.__aexit__(None, None, None)
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.mcp_app(scope, receive, send)
            return
        path: str = scope.get("path", "/")
        mcp_path = self.engine.settings.mcp_path.rstrip("/")
        if path.rstrip("/") == mcp_path:
            status: dict[str, int] = {}

            async def watch(message: MutableMapping[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    status["code"] = int(message["status"])
                await send(message)

            await self.mcp_app(scope, receive, watch)
            code = status.get("code", 0)
            if code >= 400 and code != 429:
                ip, port = scope.get("state", {}).get("chimera_addr") or ("unknown", None)
                hdrs = {k.decode().lower(): v.decode(errors="replace") for k, v in scope.get("headers", [])}
                await self.engine.protocol_error(scope.get("method", "?"), code, ip, port, hdrs)
            return
        resp = await self._decoy(Request(scope, receive))
        await resp(scope, receive, send)

    async def _decoy(self, request: Request) -> Response:
        ip, port = request.scope.get("state", {}).get("chimera_addr") or ("unknown", None)
        headers = {k.lower(): v for k, v in request.headers.items()}
        path = request.url.path
        if path == "/healthz" and ip in {"127.0.0.1", "::1"}:
            return JSONResponse({"status": "ok"})
        if await self.engine.canary_callback(path, ip, port, headers):
            if "exports" in path:
                return PlainTextResponse("AccessDenied: Request has expired", status_code=403)
            return HTMLResponse(_LOGIN_PAGE.format(name="Single Sign-On"))
        await self.engine.http_probe(path, request.method, ip, port, headers)
        if path in {"/", "/login", "/admin"}:
            return HTMLResponse(_LOGIN_PAGE.format(name=self.engine.profile.server_name))
        if path == "/.well-known/mcp.json" or path == "/.well-known/mcp":
            return JSONResponse(
                {
                    "name": self.engine.profile.server_name,
                    "version": self.engine.profile.version,
                    "endpoints": {"streamable-http": self.engine.settings.mcp_path},
                }
            )
        return PlainTextResponse("Not Found", status_code=404)


def create_app(settings: Settings | None = None) -> ChimeraApp:
    return ChimeraApp(Engine(settings or Settings.from_env()))
