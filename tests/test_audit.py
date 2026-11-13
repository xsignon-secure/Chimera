"""Regression tests for the deep audit (2026-11-13): DoS, alert delivery, canary coverage, containment."""

from __future__ import annotations

import asyncio
import base64
import time
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from chimera.detect import extract_indicators
from chimera.engine import Engine
from chimera.models import Event
from chimera.server import ChimeraApp
from chimera.telemetry import Telemetry
from chimera_responder.actions import blocklist_entry
from chimera_responder.app import create_app as create_responder
from chimera_responder.core import Responder, _now
from tests.conftest import free_port, make_settings, serve
from tests.test_e2e import responder_settings

# ---------------------------------------------------------------- DoS


def test_indicator_extraction_is_linear_on_hostile_input() -> None:
    # The old domain regex took ~10 s on 20 KB of "a." and blocked the event loop.
    for hostile in ("a." * 10_000, "1.2.3." * 4_000, "http://" + "a." * 9_000, "a@a." * 5_000, "com." * 5_000):
        start = time.perf_counter()
        extract_indicators(hostile, [], ignore_hosts=[])
        assert time.perf_counter() - start < 0.2


def test_indicator_extraction_still_finds_real_iocs() -> None:
    ind = extract_indicators("mail bob@corp.io, see evil.example.com and x.ru then 10.0.0.5", [], ignore_hosts=[])
    assert {"evil.example.com", "x.ru", "corp.io"} <= set(ind.domains)
    assert ind.emails == ["bob@corp.io"]


# ---------------------------------------------------------------- alert delivery


async def test_dead_chat_sink_does_not_delay_responder_alerts(tmp_path: Path) -> None:
    s = make_settings(
        tmp_path,
        webhook_url="http://responder.test/api/alerts",
        slack_webhook_url="http://slack.test/hook",
        egress_allowlist=["responder.test", "slack.test"],
    )
    tel = Telemetry(s, Engine(s).store, "t")
    delivered: list[str] = []

    async def fake_post(client: Any, url: str, **kw: Any) -> int:
        if "slack" in url:
            await asyncio.sleep(30)  # unreachable sink that only times out
        delivered.append(url)
        return 200

    tel._post = fake_post  # type: ignore[method-assign]
    await tel.start()
    for _ in range(5):
        await tel.emit(Event(kind="mcp.tool_call", severity="high", source_ip="10.1.1.1"))
    for _ in range(50):
        if delivered.count("http://responder.test/api/alerts") == 5:
            break
        await asyncio.sleep(0.02)
    assert delivered.count("http://responder.test/api/alerts") == 5
    for w in tel._workers:
        w.cancel()


async def test_sink_exception_does_not_kill_the_worker(tmp_path: Path) -> None:
    s = make_settings(tmp_path, webhook_url="http://responder.test/a", egress_allowlist=["responder.test"])
    tel = Telemetry(s, Engine(s).store, "t")
    calls = 0

    async def flaky(client: Any, url: str, **kw: Any) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("name resolution failed")
        return 200

    tel._post = flaky  # type: ignore[method-assign]
    await tel.start()
    await tel.emit(Event(kind="mcp.tool_call", severity="high", source_ip="10.1.1.1"))
    await tel.emit(Event(kind="mcp.tool_call", severity="high", source_ip="10.1.1.1"))
    await asyncio.wait_for(tel._queues["webhook"].join(), 2)
    assert calls == 2
    await tel.stop()


# ---------------------------------------------------------------- canaries on the HTTP surface


async def _reuse_events(engine: Engine) -> list[Event]:
    return [e for e in await engine.store.recent_events(100) if e.kind == "canary.reused"]


async def test_canary_password_typed_into_decoy_login_is_caught(engine: Engine) -> None:
    rec = await engine.canaries.issue("password", session_id="s1", source_ip="10.66.6.6", tool="get_admin_passwords")
    body = urlencode({"username": "admin", "password": rec.value}).encode()
    login = await engine.http_probe(
        "/login", "POST", "10.66.6.6", None, {"content-type": "application/x-www-form-urlencoded"}, body=body
    )
    assert login is True
    probe = [e for e in await engine.store.recent_events(100) if e.kind == "http.probe"][0]
    assert probe.severity == "high" and probe.arguments == {"path": "/login", "username": "admin"}
    assert rec.value not in probe.model_dump_json()  # the password itself is not copied into evidence
    assert [e.canary_ids for e in await _reuse_events(engine)] == [[rec.canary_id]]


async def test_canary_in_basic_auth_header_or_query_is_caught(engine: Engine) -> None:
    token = await engine.canaries.issue("vault_token", session_id="s1", source_ip="10.66.6.6", tool="t")
    pw = await engine.canaries.issue("password", session_id="s1", source_ip="10.66.6.6", tool="t", context="x")
    basic = "Basic " + base64.b64encode(f"svc:{pw.value}".encode()).decode()
    await engine.http_probe("/v1/sys", "GET", "10.66.6.6", None, {"authorization": basic})
    await engine.http_probe("/api", "GET", "10.66.6.6", None, {}, query=urlencode({"token": token.value}))
    ids = sorted(i for e in await _reuse_events(engine) for i in e.canary_ids)
    assert ids == sorted([pw.canary_id, token.canary_id])


async def test_ordinary_probe_stays_low(engine: Engine) -> None:
    assert await engine.http_probe("/robots.txt", "GET", "10.1.2.3", None, {}) is False
    probe = [e for e in await engine.store.recent_events(10) if e.kind == "http.probe"][0]
    assert probe.severity == "low"


def test_login_page_says_invalid_after_a_post(tmp_path: Path) -> None:
    port = free_port()
    with serve(ChimeraApp(Engine(make_settings(tmp_path))), port) as url:
        first = httpx.get(url + "/login")
        bad = httpx.post(url + "/login", data={"username": "root", "password": "x"})
        assert first.status_code == 200 and "Invalid" not in first.text
        assert bad.status_code == 401 and "Invalid username or password" in bad.text


# ---------------------------------------------------------------- containment


def _event(ip: str) -> Event:
    return Event(kind="mcp.tool_call", severity="critical", source_ip=ip, tool="get_admin_passwords")


async def test_isolation_expires_after_ttl(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, mode="auto", isolation_ttl_hours=1))
    inc = await r.ingest(_event("10.9.9.9"))
    assert inc and inc.status == "isolated" and inc.isolated_at
    assert await r.expire_isolations() == []  # not due yet
    inc.isolated_at = _now() - timedelta(hours=2)
    await r.store.save(inc)
    assert await r.expire_isolations() == [inc.id]
    after = await r.store.get(inc.id)
    assert after and after.status == "released" and after.isolated_at is None
    assert "10.9.9.9" not in r.actions.blocklist_path.read_text()
    log = await r.store.audit_log()
    assert any(a["actor"].startswith("policy:ttl") and a["action"] == "released" for a in log)


async def test_ttl_off_by_default_keeps_isolation(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, mode="auto"))
    inc = await r.ingest(_event("10.9.9.8"))
    assert inc
    inc.isolated_at = _now() - timedelta(days=365)
    await r.store.save(inc)
    assert await r.expire_isolations() == []


async def test_ipv6_attacker_is_blocked_by_slash_64(tmp_path: Path) -> None:
    assert blocklist_entry("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
    assert blocklist_entry("203.0.113.9") == "203.0.113.9"
    r = Responder(responder_settings(tmp_path, mode="auto"))
    inc = await r.ingest(_event("2001:db8:1:2:aaaa::1"))
    assert inc and inc.status == "isolated"
    assert "2001:db8:1:2::/64" in r.actions.blocklist_path.read_text()
    await r.release(inc.id, actor="analyst:admin")
    assert r.actions.blocklist_path.read_text().strip() == ""


async def test_ipv6_slash_64_touching_a_protected_range_is_refused(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, mode="auto", protected_networks=["2001:db8:5:5::10/128"]))
    inc = await r.ingest(_event("2001:db8:5:5::99"))
    assert inc and inc.status == "blocked_by_policy"


async def test_dedup_table_is_bounded(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path))
    r.store.SEEN_KEEP = 10  # type: ignore[misc]
    for i in range(3000):
        await r.store.first_seen(f"e{i}")
    rows = await r.store.q("SELECT COUNT(*) FROM seen")
    assert rows[0][0] < 3000


def test_dashboard_throttles_password_guessing(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path)), port) as url:
        bad = {"Authorization": "Basic " + base64.b64encode(b"admin:guess").decode()}
        good = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}
        assert httpx.get(url + "/", headers=good).status_code == 200
        codes = [httpx.get(url + "/", headers=bad).status_code for _ in range(21)]
        assert codes[:20] == [401] * 20 and codes[20] == 429
        assert httpx.get(url + "/", headers=good).status_code == 429  # global lock while under attack


def test_feed_accepts_bearer_header(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path)), port) as url:
        assert httpx.get(url + "/feeds/blocklist.txt", headers={"Authorization": "Bearer feed"}).status_code == 200
        assert httpx.get(url + "/feeds/blocklist.txt", headers={"Authorization": "Bearer nope"}).status_code == 401
        assert httpx.get(url + "/feeds/blocklist.txt", params={"token": "feed"}).status_code == 200
