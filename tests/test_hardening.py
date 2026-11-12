"""Regression tests for the second-pass security review (abuse, DoS, realism, containment logic)."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from mcp import Client

from chimera.canary import MAX_CANARIES_PER_SESSION, CanaryWatermarker
from chimera.cli import bait_config
from chimera.config import Settings
from chimera.detect import fingerprint
from chimera.engine import Engine
from chimera.fakeworld import FakeWorld
from chimera.models import Event
from chimera.server import build_mcp
from chimera.shell import FakeShell
from chimera.signing import sign
from chimera.store import Store
from chimera.telemetry import chat_escape, chat_text
from chimera_responder.app import create_app as create_responder
from chimera_responder.config import ResponderSettings
from chimera_responder.core import Responder
from tests.conftest import free_port, serve
from tests.test_e2e import responder_settings


def wm() -> CanaryWatermarker:
    return CanaryWatermarker(Store(":memory:"), "k", "https://decoy.example.test", None)


# ---------------------------------------------------------------- canaries


async def test_canary_scan_cost_is_linear_and_bounded() -> None:
    w = wm()
    for i in range(300):
        await w.issue("password", session_id=f"s{i}", source_ip="10.0.0.1", tool="t")
    junk = "A1b2C3d4" * 250_000  # 2 MB of prefix-like noise
    start = time.perf_counter()
    assert w.hits(junk) == []
    assert time.perf_counter() - start < 1.0


async def test_per_session_canary_cap_reuses_existing() -> None:
    w = wm()
    state: dict[str, Any] = {}
    ids = {
        (
            await w.issue("password", session_id="greedy", source_ip="10.0.0.1", tool="t", context=f"u{i}", cache=state)
        ).canary_id
        for i in range(400)
    }
    assert len(ids) <= MAX_CANARIES_PER_SESSION


async def test_same_question_gets_same_canary() -> None:
    w = wm()
    cache: dict[str, Any] = {}
    a = await w.issue("aws_key", session_id="s", source_ip="10.0.0.1", tool="t", context="EMP-1", cache=cache)
    b = await w.issue("aws_key", session_id="s", source_ip="10.0.0.1", tool="t", context="EMP-1", cache=cache)
    assert a.value == b.value


async def test_ssh_key_is_a_real_parseable_openssh_key() -> None:
    ssh = await wm().issue("ssh_key", session_id="s", source_ip="10.0.0.1", tool="t")
    key = load_ssh_private_key(ssh.value.encode(), password=None)
    assert key.public_key() is not None


async def test_link_preview_fetch_from_other_ip_is_not_high(engine: Engine) -> None:
    rec = await engine.canaries.issue(
        "callback_url", session_id="s", source_ip="10.66.6.6", tool="t", context="sso/login"
    )
    path = urlsplit(rec.value).path
    assert await engine.canary_callback(path, "10.66.6.6", None, {})
    assert await engine.canary_callback(path, "10.20.30.40", None, {})
    events = [e for e in await engine.store.recent_events(50) if e.kind == "canary.triggered"]
    by_ip = {e.source_ip: e.severity for e in events}
    assert by_ip["10.66.6.6"] == "high"
    assert by_ip["10.20.30.40"] == "medium"


# ---------------------------------------------------------------- honeypot input abuse


def test_fingerprint_clips_attacker_fields() -> None:
    fp = fingerprint({"name": "x" * 100_000, "version": "9" * 10_000}, "p" * 999, "ua" * 9999, {"a" * 999: {}})
    assert len(fp.client_name or "") <= 128
    assert all(len(s) < 400 for s in fp.signals)


async def test_huge_arguments_are_bounded_in_evidence(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        await c.call_tool("get_admin_passwords", {"system": "vault" + "Z" * 200_000})
    calls = [e for e in await engine.store.recent_events(50) if e.kind == "mcp.tool_call"]
    assert calls
    assert all(len(json.dumps(e.arguments)) < 6000 for e in calls)


async def test_fake_shell_pipes_and_variables() -> None:
    async def issue(kind: str, ctx: str) -> tuple[str, str | None]:
        return f"CANARY-{kind}", None

    sh = FakeShell(FakeWorld("s"), "", issue)
    assert (await sh.run("echo $HOME"))[0] == "/home/svc-deploy"
    assert (await sh.run("whoami | base64"))[0] == "c3ZjLWRlcGxveQo="
    assert "ID=" in (await sh.run("cat /etc/os-release"))[0]
    assert (await sh.run("python3 -c 'import os'"))[1] in (0, 127)


def test_chat_text_neutralises_mentions_and_links() -> None:
    hostile = "<!channel> @everyone <https://evil.example|click> *pwn*"
    out = chat_escape(hostile)
    assert "<!channel>" not in out and "@everyone" not in out and "<https" not in out
    ev = Event(kind="mcp.tool_call", severity="high", source_ip="10.0.0.9", tool="<@U123>", message=hostile)
    text = chat_text(ev)
    assert "<@U123>" not in text and "<!channel>" not in text


async def test_store_prune_bounds_disk(tmp_path: Path) -> None:
    store = Store(tmp_path / "x.db")
    for i in range(30):
        await store.add_event(Event(kind="mcp.tool_call", severity="low", source_ip="10.0.0.1", session_id=f"s{i}"))
    await store.prune(retention_days=90, max_events=10, canary_days=180, max_canaries=10)
    assert len(await store.recent_events(100)) == 10


# ---------------------------------------------------------------- configuration


def test_placeholders_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Settings.model_validate({"data_dir": tmp_path, "webhook_secret": "change-me-to-a-long-random-string"})
    with pytest.raises(ValueError):
        ResponderSettings.model_validate({"data_dir": tmp_path, "admin_password": "change-me-too"})


def test_bait_config_formats() -> None:
    url = "http://mcp-aws-prod.corp.example:8000/mcp"
    assert bait_config("AWS-Prod-Root-MCP", url, "claude")["mcpServers"] == {
        "AWS-Prod-Root-MCP": {"type": "http", "url": url}
    }
    assert "servers" in bait_config("AWS-Prod-Root-MCP", url, "vscode")


def test_compose_keeps_responder_secrets_out_of_the_honeypot() -> None:
    compose = (Path(__file__).parent.parent / "docker-compose.yml").read_text()
    honeypot = compose.split("\n  honeypot:")[1].split("\n  responder:")[0]
    assert "env_file:" not in honeypot
    assert "RESPONDER_" not in honeypot
    assert "RESPONDER_ALERTS_ONLY_NETWORKS" in compose


# ---------------------------------------------------------------- responder


def _event(ip: str, severity: str = "critical") -> Event:
    return Event(kind="mcp.tool_call", severity=severity, source_ip=ip, tool="get_admin_passwords")  # type: ignore[arg-type]


async def test_released_attacker_who_returns_is_contained_again(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, mode="auto"))
    inc = await r.ingest(_event("10.5.5.5"))
    assert inc and inc.status == "isolated"
    await r.release(inc.id, actor="analyst:admin")
    again = await r.ingest(_event("10.5.5.5"))
    assert again and again.status == "isolated"


async def test_release_and_reject_respect_state(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, mode="approve"))
    inc = await r.ingest(_event("10.5.5.6"))
    assert inc and inc.status == "pending_approval"
    with pytest.raises(ValueError):
        await r.release(inc.id, actor="mcp-agent")
    await r.approve(inc.id, actor="mcp-agent: confirmed theft")
    with pytest.raises(ValueError):
        await r.reject(inc.id, actor="mcp-agent", reason="oops")


async def test_isolation_cap_survives_restart(tmp_path: Path) -> None:
    rs = responder_settings(tmp_path, mode="auto", max_isolations_per_hour=1)
    first = await Responder(rs).ingest(_event("10.7.7.1"))
    second = await Responder(rs).ingest(_event("10.7.7.2"))  # new process, same database
    assert first and first.status == "isolated"
    assert second and second.status == "pending_approval"


def test_non_ascii_credentials_get_401_not_500(tmp_path: Path) -> None:
    rport = free_port()
    with serve(create_responder(responder_settings(tmp_path, admin_password="pässwörd")), rport) as rurl:
        good = base64.b64encode("admin:pässwörd".encode()).decode()
        bad = base64.b64encode("admin:wröng".encode()).decode()
        assert httpx.get(rurl + "/", headers={"Authorization": f"Basic {good}"}).status_code == 200
        assert httpx.get(rurl + "/", headers={"Authorization": f"Basic {bad}"}).status_code == 401
        assert httpx.get(rurl + "/", headers={"Authorization": "Basic %%%"}).status_code == 401
        raw = httpx.get(rurl + "/mcp/", headers={"Authorization": b"Bearer \xe4\xf6"})
        assert raw.status_code == 401
        assert httpx.get(rurl + "/feeds/blocklist.txt", params={"token": "fëed"}).status_code == 401


def test_alerts_only_network_cannot_reach_console(tmp_path: Path) -> None:
    rport = free_port()
    rs = responder_settings(tmp_path, alerts_only_networks=["127.0.0.0/8"])
    with serve(create_responder(rs), rport) as rurl:
        auth = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}
        assert httpx.get(rurl + "/", headers=auth).status_code == 404
        assert httpx.get(rurl + "/feeds/blocklist.txt?token=feed").status_code == 404
        assert httpx.post(rurl + "/mcp/", headers={"Authorization": "Bearer blue"}).status_code == 404
        body = json.dumps({"kind": "mcp.tool_call", "severity": "high", "source_ip": "10.8.8.8"}).encode()
        assert httpx.post(rurl + "/api/alerts", content=body, headers=sign("shh", body)).status_code == 200
