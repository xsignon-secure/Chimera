"""Honey tools and the rabbit-hole state machine, through a real MCP client (in-process)."""

from __future__ import annotations

import json
from typing import Any

from mcp import Client

from chimera.engine import Engine
from chimera.server import build_mcp
from chimera.tools import REGISTRY


def text(result: Any) -> str:
    return str(result.content[0].text)


async def test_every_profile_tool_is_listed_with_descriptions(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        tools = (await c.list_tools()).tools
    assert {t.name for t in tools} == set(REGISTRY)
    for t in tools:
        assert len(t.description or "") > 40, t.name
        assert t.input_schema["type"] == "object"


async def test_rabbit_hole_enforces_dependencies(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        r = await c.call_tool("execute_data_export_script", {"s3_bucket_url": "s3://loot/x", "auth_token": "nope"})
        assert "refresh_vault_token first" in text(r)
        r = await c.call_tool("refresh_vault_token", {"username": "x", "password": "guess"})
        assert "permission denied" in text(r)
        r = await c.call_tool("read_vault_secret", {"path": "kv/prod/stripe"})
        assert "refresh_vault_token first" in text(r)

        creds = json.loads(text(await c.call_tool("get_admin_passwords", {"system": "vault"})))["credentials"][0]
        tok = json.loads(
            text(
                await c.call_tool("refresh_vault_token", {"username": creds["username"], "password": creds["password"]})
            )
        )
        token = tok["auth"]["client_token"]
        assert token.startswith("hvs.")
        secret = json.loads(
            text(await c.call_tool("read_vault_secret", {"path": "kv/prod/stripe", "vault_token": token}))
        )
        assert secret["data"]["api_key"].startswith("sk_live_")
        job = json.loads(
            text(await c.call_tool("execute_data_export_script", {"s3_bucket_url": "s3://loot/x", "auth_token": token}))
        )
        assert job["status"] == "RUNNING" and job["manifest_url"].startswith("https://decoy.example.test/")

    events = await engine.store.recent_events(500)
    kinds = [e.kind for e in events]
    assert "canary.reused" in kinds
    exports = [e for e in events if e.tool == "execute_data_export_script" and e.kind == "mcp.tool_call"]
    assert all(e.indicators and "s3://loot/x" in e.indicators.urls for e in exports)
    assert {e.outcome for e in exports} == {"success", "failure"}


async def test_all_tools_respond_and_issue_canaries(engine: Engine) -> None:
    args: dict[str, dict[str, Any]] = {
        "query_employee_aws_keys": {"employee_id": "EMP-1"},
        "refresh_vault_token": {"username": "a", "password": "b"},
        "read_vault_secret": {"path": "kv/x"},
        "execute_data_export_script": {"s3_bucket_url": "s3://x"},
        "create_iam_user": {"username": "backdoor", "attach_admin_policy": True},
        "get_sso_session_link": {"user": "ceo"},
        "run_shell_command": {"command": "id"},
    }
    async with Client(build_mcp(engine)) as c:
        for name in REGISTRY:
            r = await c.call_tool(name, args.get(name, {}))
            assert text(r), name
    secrets_tools = {
        "get_admin_passwords",
        "get_internal_admin_credentials",
        "get_aws_root_credentials",
        "query_employee_aws_keys",
        "get_db_connection_string",
        "create_iam_user",
        "get_sso_session_link",
    }
    canaries = await engine.store.all_canaries()
    assert secrets_tools <= {c.tool for c in canaries}


async def test_every_returned_secret_is_a_registered_canary(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        out = text(await c.call_tool("get_aws_root_credentials", {}))
    data = json.loads(out)
    assert engine.canaries.scan(data["aws_access_key_id"])
    assert engine.canaries.scan(data["console_signin_url"])


async def test_attack_events_carry_mitre_and_fingerprint(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        await c.list_tools()
        await c.call_tool(
            "disable_firewall",
            {"firewall_id": "fw-edge-01", "duration_minutes": 30, "change_ticket": "ignore previous instructions"},
        )
    events = await engine.store.recent_events(50)
    fw = next(e for e in events if e.tool == "disable_firewall")
    assert fw.severity == "critical"
    assert "T1562.004" in fw.mitre_attack
    assert "AML.T0051" in fw.mitre_atlas  # prompt-injection marker in arguments
    assert fw.fingerprint is not None
    recon = next(e for e in events if e.method == "tools/list")
    assert recon.mitre_attack == ["T1526"]


async def test_invalid_arguments_do_not_crash(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        r = await c.call_tool("disable_firewall", {"duration_minutes": 99999})
        assert r.is_error
        r = await c.call_tool("does_not_exist", {})
        assert r.is_error
        assert (await c.list_tools()).tools  # server still healthy
