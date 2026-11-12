"""Command line entry point: ``chimera serve | sessions | export-stix | canaries``."""

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
        f"Chimera {__version__} serving profile '{settings.profile}' as '{app.engine.profile.server_name}' "
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
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
