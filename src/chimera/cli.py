"""Command line entry point: ``chimera serve | sessions | export-stix | canaries | bait``."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from chimera import __version__
from chimera.config import Settings
from chimera.profiles import PROFILES


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    settings = Settings.from_env()
    if args.profile:
        settings.profile = args.profile
    if args.port:
        settings.port = args.port
    if args.transport == "stdio":
        from chimera.engine import Engine
        from chimera.server import build_mcp

        settings.log_stdout = False  # stdout is the MCP channel
        engine = Engine(settings)
        server = build_mcp(engine)

        async def run() -> None:
            await engine.start()
            try:
                await server.run_stdio_async()
            finally:
                await engine.stop()

        asyncio.run(run())
        return

    from chimera.server import create_app

    app = create_app(settings)
    print(
        f"Chimera {__version__} serving profile '{settings.profile}' as '{app.engine.server_name}' "
        f"on {settings.host}:{settings.port}{settings.mcp_path}",
        file=sys.stderr,
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="warning",
        server_header=False,
        proxy_headers=False,
        date_header=True,
    )


def _sessions(_: argparse.Namespace) -> None:
    from chimera.store import Store

    store = Store(Settings.from_env().db_path)
    rows = asyncio.run(store.list_sessions())
    for r in rows:
        fp = r.fingerprint
        print(
            f"{r.last_seen:%Y-%m-%d %H:%M:%S}  {r.session_id}  {r.source_ip:<16} {r.max_severity:<8} "
            f"reqs={r.request_count:<4} client={(fp.client_name if fp else None) or '-'}"
            f"({fp.classification if fp else '-'})  tools={','.join(r.tool_calls) or '-'}"
        )


def _export(args: argparse.Namespace) -> None:
    from chimera.stix import session_bundle
    from chimera.store import Store

    store = Store(Settings.from_env().db_path)
    events = asyncio.run(store.events_for_session(args.session_id))
    if not events:
        sys.exit(f"no events for session {args.session_id}")
    print(json.dumps(session_bundle(args.session_id, events), indent=2))


def _canaries(_: argparse.Namespace) -> None:
    from chimera.store import Store

    store = Store(Settings.from_env().db_path)
    for c in asyncio.run(store.all_canaries()):
        print(
            f"{c.issued_at:%Y-%m-%d %H:%M:%S}  {c.canary_id}  {c.kind:<12} session={c.session_id} "
            f"ip={c.source_ip} tool={c.tool} external={c.external}"
        )


def bait_config(name: str, url: str, fmt: str) -> dict[str, object]:
    """An MCP client config that points at the decoy, to plant where an intruder will look."""
    if fmt == "vscode":
        return {"servers": {name: {"type": "http", "url": url}}}
    return {"mcpServers": {name: {"type": "http", "url": url}}}


def _bait(args: argparse.Namespace) -> None:
    from chimera.profiles import PROFILES as profiles

    settings = Settings.from_env()
    if args.profile:
        settings.profile = args.profile
    if "localhost" in settings.public_base_url or "127.0.0.1" in settings.public_base_url:
        print("warning: CHIMERA_PUBLIC_BASE_URL points at localhost; set the URL attackers will use", file=sys.stderr)
    name = settings.server_name or profiles[settings.profile].server_name
    url = settings.public_base_url.rstrip("/") + settings.mcp_path
    print(json.dumps(bait_config(name, url, args.format), indent=2))


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(prog="chimera", description="Project Chimera MCP honeypot")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="run the honeypot")
    serve.add_argument("--transport", choices=["http", "stdio"], default="http")
    serve.add_argument("--profile", choices=sorted(PROFILES))
    serve.add_argument("--port", type=int)
    serve.set_defaults(func=_serve)
    sub.add_parser("sessions", help="list attacker sessions").set_defaults(func=_sessions)
    exp = sub.add_parser("export-stix", help="export a session as a STIX 2.1 bundle")
    exp.add_argument("session_id")
    exp.set_defaults(func=_export)
    sub.add_parser("canaries", help="list issued canaries").set_defaults(func=_canaries)
    bait = sub.add_parser("bait", help="print an .mcp.json breadcrumb that points at the decoy")
    bait.add_argument("--format", choices=["claude", "cursor", "vscode"], default="claude")
    bait.add_argument("--profile", choices=sorted(PROFILES))
    bait.set_defaults(func=_bait)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
