"""Security gates: the honeypot must never execute, never pivot, never leak real data."""

from __future__ import annotations

import ast
import ipaddress
import json
import re
from pathlib import Path

import httpx
import pytest
from mcp import Client

from chimera.egress import EgressDenied, EgressGuard
from chimera.engine import Engine
from chimera.models import Event
from chimera.server import ClientAddressMiddleware, build_mcp
from chimera.signing import sign, verify
from chimera.stix import session_bundle
from chimera.telemetry import to_cef
from chimera.tools import REGISTRY

SRC = Path(__file__).resolve().parents[1] / "src"
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_MODULES = {"subprocess", "pickle", "marshal", "shelve", "pty", "ctypes", "telnetlib", "paramiko"}
FORBIDDEN_ATTRS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "spawnl"),
    ("os", "fork"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
}
SOCKET_ALLOWED = {"telemetry.py"}  # UDP syslog to a configured collector only


def _python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_code_execution_primitives(path: Path) -> None:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"{path}:{node.lineno} calls {node.func.id}"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert (node.value.id, node.attr) not in FORBIDDEN_ATTRS, f"{path}:{node.lineno}"
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for n in names:
                root = n.split(".")[0]
                assert root not in FORBIDDEN_MODULES, f"{path}:{node.lineno} imports {n}"
                if root == "socket":
                    assert path.name in SOCKET_ALLOWED, f"{path} must not open sockets"


def test_egress_guard_blocks_unlisted_hosts() -> None:
    g = EgressGuard(["siem.corp.example"])
    g.check("https://siem.corp.example/hook")
    for bad in ["https://evil.example/", "http://169.254.169.254/latest/meta-data", "http://siem.corp.example.evil/"]:
        with pytest.raises(EgressDenied):
            g.check(bad)


async def test_egress_guard_applies_to_client_requests() -> None:
    g = EgressGuard([])
    async with g.client() as client:
        with pytest.raises(EgressDenied):
            await client.get("http://example.com/")


async def test_attacker_urls_are_never_fetched(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exfil URLs, shell curl targets and SSRF bait are recorded, never requested."""
    called: list[str] = []

    async def spy(self: httpx.AsyncClient, request: httpx.Request, **kw: object) -> httpx.Response:
        called.append(str(request.url))
        return httpx.Response(200)

    monkeypatch.setattr(httpx.AsyncClient, "send", spy)
    async with Client(build_mcp(engine)) as c:
        await c.call_tool("execute_data_export_script", {"s3_bucket_url": "http://169.254.169.254/latest"})
        await c.call_tool("run_shell_command", {"command": "curl http://10.0.0.1:8080/admin; wget http://x.test"})
    assert called == []


async def test_responses_contain_no_public_ips(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        blob = ""
        for name in ["get_internal_admin_credentials", "list_admin_users", "get_db_connection_string"]:
            blob += (await c.call_tool(name, {})).content[0].text
        blob += (await c.call_tool("run_shell_command", {"command": "cat /etc/hosts; ip a"})).content[0].text
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        addr = ipaddress.ip_address(ip)
        assert addr.is_private or addr.is_loopback, ip


async def test_no_honeypot_tells_in_tool_surface(engine: Engine) -> None:
    async with Client(build_mcp(engine)) as c:
        listing = json.dumps([t.model_dump() for t in (await c.list_tools()).tools]).lower()
        info = (c.server_info.name if c.server_info else "").lower()
    for tell in ["honeypot", "chimera", "canary", "decoy", "fake", "trap"]:
        assert tell not in listing and tell not in info, tell


def test_xff_only_trusted_from_proxy() -> None:
    mw = ClientAddressMiddleware(lambda *a: None, ["10.0.0.2/32"])  # type: ignore[arg-type, return-value]
    spoof = {"client": ("203.0.113.5", 1), "headers": [(b"x-forwarded-for", b"1.1.1.1")]}
    assert mw.resolve(spoof)[0] == "203.0.113.5"
    via = {"client": ("10.0.0.2", 1), "headers": [(b"x-forwarded-for", b"9.9.9.9, 198.51.100.4")]}
    assert mw.resolve(via)[0] == "198.51.100.4"


def test_signing_roundtrip() -> None:
    body = b'{"a":1}'
    h = sign("k", body)
    assert verify("k", body, h["X-Chimera-Signature"], h["X-Chimera-Timestamp"])
    assert not verify("k", body + b" ", h["X-Chimera-Signature"], h["X-Chimera-Timestamp"])
    assert not verify("other", body, h["X-Chimera-Signature"], h["X-Chimera-Timestamp"])
    assert not verify("", body, h["X-Chimera-Signature"], h["X-Chimera-Timestamp"])


def test_cef_escaping_and_stix() -> None:
    e = Event(
        kind="mcp.tool_call",
        severity="critical",
        source_ip="10.1.2.3",
        session_id="s_1",
        tool="disable_firewall",
        mitre_attack=["T1562.004"],
        mitre_atlas=["AML.T0053"],
        message="a=b|c\nnext",
    )
    cef = to_cef(e, "1.0.0")
    assert cef.startswith("CEF:0|ProjectChimera|MCP-Honeypot|1.0.0|mcp.tool_call|")
    assert "msg=a\\=b|c next" in cef and "\n" not in cef
    bundle = session_bundle("s_1", [e])
    types = {o["type"] for o in bundle["objects"]}
    assert {"identity", "indicator", "attack-pattern", "relationship", "sighting"} <= types


def test_registry_mitre_ids_are_well_formed() -> None:
    for t in REGISTRY.values():
        for tid in t.attack:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), (t.name, tid)
        for tid in t.atlas:
            assert re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", tid), (t.name, tid)
