"""Wazuh active response, against a stand-in that returns the exact payloads a real
Wazuh 4.14 manager returned in our live test (manager + agent in Docker, 2026-11-12)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from chimera.models import Event
from chimera_responder.actions import wazuh_timeout
from chimera_responder.config import ResponderSettings
from chimera_responder.core import Responder
from tests.conftest import free_port, serve

AGENTS = {"001"}
COMMANDS = {"!firewall-drop", "firewall-drop3600"}  # "!script" or a manager <active-response> name


def fake_wazuh(calls: list[dict[str, Any]]) -> Starlette:
    async def authenticate(request: Request) -> JSONResponse:
        if request.headers.get("authorization") != "Basic " + base64.b64encode(b"wazuh:wazuh").decode():
            return JSONResponse({"title": "Unauthorized", "detail": "Invalid credentials"}, status_code=401)
        return JSONResponse({"data": {"token": "jwt-token"}, "error": 0})

    async def active_response(request: Request) -> JSONResponse:
        if request.headers.get("authorization") != "Bearer jwt-token":
            return JSONResponse({"title": "Unauthorized"}, status_code=401)
        body = await request.json()
        calls.append({"params": dict(request.query_params), "body": body})
        wanted = request.query_params.get("agents_list", ",".join(sorted(AGENTS))).split(",")
        if body["command"] not in COMMANDS:
            err = {"code": 1652, "message": "The command used is not defined in the configuration."}
            failed = [{"error": err, "id": wanted}]
            ok: list[str] = []
        else:
            ok = [a for a in wanted if a in AGENTS]
            missing = [a for a in wanted if a not in AGENTS]
            err = {"code": 1701, "message": "Agent does not exist"}
            failed = [{"error": err, "id": missing}] if missing else []
        return JSONResponse(
            {
                "data": {
                    "affected_items": ok,
                    "total_affected_items": len(ok),
                    "total_failed_items": sum(len(f["id"]) for f in failed),
                    "failed_items": failed,
                },
                "message": "AR command was sent to all agents" if ok else "AR command was not sent to any agent",
                "error": 0 if ok and not failed else 1,
            }
        )

    return Starlette(
        routes=[
            Route("/security/user/authenticate", authenticate, methods=["POST"]),
            Route("/active-response", active_response, methods=["PUT"]),
        ]
    )


def settings(tmp_path: Path, url: str, **kw: Any) -> ResponderSettings:
    base: dict[str, Any] = {
        "data_dir": tmp_path / "resp",
        "mode": "auto",
        "actions": ["wazuh"],
        "wazuh_url": url,
        "wazuh_user": "wazuh",
        "wazuh_password": "wazuh",
        "wazuh_agents": "001",
        "wazuh_command": "firewall-drop3600",
    }
    base.update(kw)
    return ResponderSettings.model_validate(base)


def attack(ip: str = "10.66.6.6") -> Event:
    return Event(kind="mcp.tool_call", severity="critical", source_ip=ip, tool="get_aws_root_credentials")


async def test_wazuh_isolates_with_the_documented_request(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    with serve(fake_wazuh(calls), free_port()) as url:
        inc = await Responder(settings(tmp_path, url)).ingest(attack())
    assert inc and inc.status == "isolated"
    assert calls[0]["params"] == {"agents_list": "001"}
    assert calls[0]["body"]["command"] == "firewall-drop3600"
    assert calls[0]["body"]["alert"]["data"]["srcip"] == "10.66.6.6"
    assert "agents affected: 1 (001)" in inc.actions[-1]["detail"]
    assert "auto-release after 3600s" in inc.actions[-1]["detail"]


async def test_wazuh_all_agents_sends_no_agent_filter(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    with serve(fake_wazuh(calls), free_port()) as url:
        inc = await Responder(settings(tmp_path, url, wazuh_agents="all")).ingest(attack())
    assert inc and inc.status == "isolated"
    assert calls[0]["params"] == {}


async def test_http_200_with_no_agent_affected_is_a_failure(tmp_path: Path) -> None:
    # Real Wazuh answers HTTP 200 even when it blocked nothing. That must never read as "isolated".
    with serve(fake_wazuh([]), free_port()) as url:
        unknown_agent = await Responder(settings(tmp_path, url, wazuh_agents="999")).ingest(attack("10.1.1.1"))
        unknown_cmd = await Responder(settings(tmp_path, url, wazuh_command="firewall-drop7200")).ingest(
            attack("10.1.1.2")
        )
    assert unknown_agent and unknown_agent.status == "failed"
    assert "Agent does not exist" in unknown_agent.actions[-1]["detail"]
    assert unknown_cmd and unknown_cmd.status == "failed"
    assert "not defined in the configuration" in unknown_cmd.actions[-1]["detail"]


async def test_bad_wazuh_credentials_fail_cleanly(tmp_path: Path) -> None:
    with serve(fake_wazuh([]), free_port()) as url:
        inc = await Responder(settings(tmp_path, url, wazuh_password="wrong")).ingest(attack())
    assert inc and inc.status == "failed"
    assert "401" in inc.actions[-1]["detail"]


async def test_release_is_honest_about_wazuh_timeouts(tmp_path: Path) -> None:
    with serve(fake_wazuh([]), free_port()) as url:
        timed = Responder(settings(tmp_path / "a", url))
        inc = await timed.ingest(attack())
        assert inc
        rel = await timed.release(inc.id, actor="analyst:admin")
        assert rel.actions[-1]["ok"] and "automatically (3600s" in rel.actions[-1]["detail"]

        forever = Responder(settings(tmp_path / "b", url, wazuh_command="!firewall-drop"))
        inc = await forever.ingest(attack())
        assert inc and inc.status == "isolated"
        assert "permanent" in inc.actions[-1]["detail"]
        rel = await forever.release(inc.id, actor="analyst:admin")
        assert not rel.actions[-1]["ok"]
        assert "iptables -D INPUT -s 10.66.6.6 -j DROP" in rel.actions[-1]["detail"]


def test_wazuh_timeout_parsing() -> None:
    assert wazuh_timeout("firewall-drop3600") == 3600
    assert wazuh_timeout("firewall-drop60") == 60
    assert wazuh_timeout("!firewall-drop") == 0
    assert wazuh_timeout("host-deny") == 0
