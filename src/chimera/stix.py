"""STIX 2.1 export, so sessions can be shared with MISP, OpenCTI or any TIP."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from chimera.models import Event

_NS = uuid.UUID("6f1c2b8e-61a4-4b0a-9a39-2c1f7e3d9b51")


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + key)}"


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def session_bundle(session_id: str, events: list[Event]) -> dict[str, Any]:
    now = _ts(datetime.now(UTC))
    objects: list[dict[str, Any]] = []
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _id("identity", "chimera"),
        "created": now,
        "modified": now,
        "name": "Project Chimera MCP Honeypot",
        "identity_class": "system",
    }
    objects.append(identity)
    ips = sorted({e.source_ip for e in events if e.source_ip and e.source_ip not in {"stdio", "unknown"}})
    refs: list[str] = []
    for ip in ips:
        version = "ipv6-addr" if ":" in ip else "ipv4-addr"
        obs = {"type": version, "spec_version": "2.1", "id": _id(version, ip), "value": ip}
        objects.append(obs)
        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _id("indicator", ip),
            "created": now,
            "modified": now,
            "name": f"MCP honeypot interaction from {ip}",
            "pattern": f"[{version}:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
            "labels": ["mcp-honeypot", session_id],
        }
        objects.append(ind)
        refs.append(str(ind["id"]))
    urls = sorted({u for e in events if e.indicators for u in e.indicators.urls})
    for url in urls:
        safe = url.replace("\\", "\\\\").replace("'", "\\'")
        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _id("indicator", url),
            "created": now,
            "modified": now,
            "name": "Exfiltration destination supplied to MCP honeypot",
            "pattern": f"[url:value = '{safe}']",
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
        }
        objects.append(ind)
        refs.append(str(ind["id"]))
    techniques = sorted({t for e in events for t in e.mitre_attack + e.mitre_atlas})
    for tech in techniques:
        source = "mitre-atlas" if tech.startswith("AML.") else "mitre-attack"
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": _id("attack-pattern", tech),
            "created": now,
            "modified": now,
            "name": tech,
            "external_references": [{"source_name": source, "external_id": tech}],
        }
        objects.append(ap)
        for ind_id in refs:
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _id("relationship", ind_id + tech),
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap["id"],
                }
            )
    if events:
        objects.append(
            {
                "type": "sighting",
                "spec_version": "2.1",
                "id": _id("sighting", session_id),
                "created": now,
                "modified": now,
                "first_seen": _ts(events[0].timestamp),
                "last_seen": _ts(events[-1].timestamp),
                "count": len(events),
                "sighting_of_ref": refs[0] if refs else identity["id"],
                "where_sighted_refs": [identity["id"]],
                "description": f"Session {session_id}: " + ", ".join(sorted({e.tool for e in events if e.tool})),
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
