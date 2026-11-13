"""1.2.0 features: sensor heartbeat and silence alerts, metrics page, phone alerts, dashboard search and export."""

from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from chimera.engine import Engine
from chimera.models import Event
from chimera.signing import sign
from chimera.telemetry import Telemetry
from chimera_responder.app import create_app as create_responder
from chimera_responder.core import Responder, _now
from tests.conftest import free_port, make_settings, serve
from tests.test_e2e import responder_settings

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}


def _post(url: str, event: Event) -> httpx.Response:
    body = event.model_dump_json().encode()
    return httpx.post(url + "/api/alerts", content=body, headers=sign("shh", body))


def _attack(ip: str, tool: str = "get_admin_passwords", severity: str = "critical") -> Event:
    return Event(kind="mcp.tool_call", severity=severity, source_ip=ip, tool=tool)  # type: ignore[arg-type]


# ---------------------------------------------------------------- heartbeat


async def test_honeypot_sends_signed_heartbeats(tmp_path: Path) -> None:
    s = make_settings(
        tmp_path,
        webhook_url="http://responder.test/a",
        webhook_secret="shh",
        heartbeat_seconds=1,
        egress_allowlist=["responder.test"],
    )
    tel = Telemetry(s, Engine(s).store, "9.9.9")
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        assert request.headers["X-Chimera-Signature"].startswith("sha256=")
        return httpx.Response(200)

    real = tel.guard.client
    tel.guard.client = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)  # type: ignore[method-assign]
    await tel.start()
    for _ in range(40):
        if seen:
            break
        await asyncio.sleep(0.05)
    await tel.stop()
    assert seen and seen[0]["kind"] == "sensor.heartbeat"
    assert seen[0]["arguments"]["version"] == "9.9.9"
    assert not [e for e in await tel.store.recent_events(10) if e.kind == "sensor.heartbeat"]  # never stored


def test_heartbeat_is_not_an_incident_and_shows_on_dashboard(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path)), port) as url:
        assert "waiting for first heartbeat" in httpx.get(url + "/", headers=AUTH).text
        hb = Event(kind="sensor.heartbeat", arguments={"version": "1.2.0", "alerts_sent_ok": 7})
        assert _post(url, hb).json() == {"heartbeat": "ok"}
        page = httpx.get(url + "/", headers=AUTH).text
        assert "Sensor: <b>online</b>" in page and "No matching incidents" in page


async def test_silent_sensor_alerts_once_then_recovers(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, sensor_silence_minutes=5, ntfy_url="https://ntfy.test/topic"))
    sent: list[tuple[str, bool]] = []

    async def fake_notify(text: str, title: str = "", urgent: bool = False, link: str = "") -> None:
        sent.append((title, urgent))

    r.actions.notify = fake_notify  # type: ignore[method-assign]
    assert await r.check_sensor() == "unknown"  # no heartbeat yet: never alarm on a fresh start
    r.record_heartbeat(Event(kind="sensor.heartbeat"))
    assert await r.check_sensor() == "ok"
    r.sensor["last_seen"] = _now() - timedelta(minutes=6)
    assert await r.check_sensor() == "silent"
    assert await r.check_sensor() == "silent"  # no repeat
    r.record_heartbeat(Event(kind="sensor.heartbeat"))
    assert await r.check_sensor() == "ok"
    assert sent == [("Chimera sensor silent", True), ("Chimera sensor back", False)]


# ---------------------------------------------------------------- metrics


def test_metrics_page_requires_token_and_reports_state(tmp_path: Path) -> None:
    port = free_port()
    rs = responder_settings(tmp_path, mode="auto", metrics_token="m3tr1cs")
    with serve(create_responder(rs), port) as url:
        assert httpx.get(url + "/metrics").status_code == 401
        assert httpx.get(url + "/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
        _post(url, _attack("10.4.4.4"))
        bad = httpx.post(url + "/api/alerts", content=b"{}", headers=sign("wrong", b"{}"))
        assert bad.status_code == 401
        text = httpx.get(url + "/metrics", headers={"Authorization": "Bearer m3tr1cs"}).text
        assert 'chimera_incidents{status="isolated"} 1' in text
        assert 'chimera_incidents_by_severity{severity="critical"} 1' in text
        assert "chimera_alerts_received_total 1" in text
        assert "chimera_alerts_rejected_total 1" in text
        assert "chimera_isolations_total 1" in text
        assert "chimera_sensor_up -1" in text
        assert "# TYPE chimera_alerts_received_total counter" in text


def test_metrics_disabled_without_token(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path)), port) as url:
        assert httpx.get(url + "/metrics").status_code == 401
        assert httpx.get(url + "/metrics", headers={"Authorization": "Bearer x"}).status_code == 401


# ---------------------------------------------------------------- phone alerts


async def test_ntfy_push_has_title_priority_and_link(tmp_path: Path) -> None:
    r = Responder(responder_settings(tmp_path, ntfy_url="https://ntfy.test/chimera-x", public_url="https://dash.test"))
    got: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        got.append(request)
        return httpx.Response(200)

    real = r.actions.guard.client
    r.actions.guard.client = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)  # type: ignore[method-assign]
    inc = await r.ingest(_attack("10.6.6.6", tool="*evil*`tool`"))
    assert inc and inc.status == "pending_approval"
    assert len(got) == 1
    req = got[0]
    assert str(req.url) == "https://ntfy.test/chimera-x"
    assert req.headers["Priority"] == "urgent"
    assert req.headers["Click"] == f"https://dash.test/incidents/{inc.id}"
    assert inc.id in req.headers["Title"]
    body = req.content.decode()
    assert "10.6.6.6" in body and "*" not in body and "`" not in body


def test_ntfy_host_is_on_the_egress_allowlist(tmp_path: Path) -> None:
    rs = responder_settings(tmp_path, ntfy_url="https://ntfy.sh/chimera-abc")
    assert "ntfy.sh" in rs.egress_hosts


# ---------------------------------------------------------------- dashboard search and export


def test_dashboard_search_filters_and_export(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path, mode="approve")), port) as url:
        _post(url, _attack("10.1.1.1", tool="get_aws_root_credentials"))
        _post(url, _attack("10.2.2.2", tool='=HYPERLINK("http://x")', severity="medium"))
        page = httpx.get(url + "/", headers=AUTH, params={"q": "aws_root"}).text
        assert "10.1.1.1" in page and "10.2.2.2" not in page
        page = httpx.get(url + "/", headers=AUTH, params={"severity": "medium"}).text
        assert "10.2.2.2" in page and "10.1.1.1" not in page
        page = httpx.get(url + "/", headers=AUTH, params={"status": "pending_approval"}).text
        assert "10.1.1.1" in page and "10.2.2.2" not in page
        assert httpx.get(url + "/export.csv").status_code == 401
        data = httpx.get(url + "/export.json", headers=AUTH).json()
        assert {d["source_ip"] for d in data} == {"10.1.1.1", "10.2.2.2"}
        assert all("approval_nonce" not in d for d in data)
        rows = list(csv.DictReader(io.StringIO(httpx.get(url + "/export.csv", headers=AUTH).text)))
        evil = next(r for r in rows if r["source_ip"] == "10.2.2.2")
        assert evil["tools"].startswith("'=")  # spreadsheet formula neutralised
        filtered = httpx.get(url + "/export.json", headers=AUTH, params={"q": "10.1.1.1"}).json()
        assert [d["source_ip"] for d in filtered] == ["10.1.1.1"]


def test_search_box_escapes_input(tmp_path: Path) -> None:
    port = free_port()
    with serve(create_responder(responder_settings(tmp_path)), port) as url:
        page = httpx.get(url + "/", headers=AUTH, params={"q": "'><script>alert(1)</script>"}).text
        assert "<script>alert(1)" not in page
