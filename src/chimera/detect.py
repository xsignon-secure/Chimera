"""Detection helpers: agent fingerprinting, IOC extraction and severity scoring."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any, cast

from chimera.config import SEVERITY_RANK, Severity
from chimera.models import AgentFingerprint, Indicators

_AI_CLIENTS = (
    "claude",
    "cursor",
    "cline",
    "roo",
    "windsurf",
    "continue",
    "copilot",
    "vscode",
    "goose",
    "langchain",
    "langgraph",
    "openai",
    "autogen",
    "crewai",
    "llamaindex",
    "llama-index",
    "zed",
    "mcp-remote",
    "n8n",
    "dify",
    "agent",
    "gpt",
    "gemini",
    "smolagents",
    "pydantic-ai",
    "fast-agent",
)
_DEV_CLIENTS = ("inspector", "mcp-cli", "mcptools", "postman")
_SCANNERS = (
    "nuclei",
    "zgrab",
    "masscan",
    "nmap",
    "censys",
    "shodan",
    "httpx-toolkit",
    "nikto",
    "gobuster",
    "ffuf",
    "wfuzz",
    "sqlmap",
    "mcp-scan",
    "mcpscan",
    "expanse",
    "paloalto",
)
_SCRIPTS = (
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "aiohttp",
    "okhttp",
    "java/",
    "node-fetch",
    "axios",
    "libwww",
    "powershell",
)

_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)",
    r"disregard (the |all )?(previous|prior|system)",
    r"you are now",
    r"system prompt",
    r"developer mode",
    r"do anything now|\bDAN\b",
    r"<\|im_(start|end)\|>",
    r"\[/?INST\]",
    r"BEGIN (SYSTEM|ADMIN) (PROMPT|INSTRUCTIONS)",
    r"act as (an? )?(admin|root|unrestricted)",
    r"exfiltrat",
    r"without (asking|telling) the user",
    r"do not (tell|inform|mention) (the )?user",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]
_URL_RE = re.compile(r"\b(?:https?|s3|gs|ftp|wss?)://[^\s'\"<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|xyz|top|app|dev|cloud|site|info|"
    r"biz|co|me|sh|link|online|tk|pw|cc|su)\b",
    re.IGNORECASE,
)


def flatten(value: Any, limit: int = 20000) -> str:
    """Concatenate every string inside a JSON-like structure (bounded)."""
    out: list[str] = []
    size = 0

    def walk(v: Any) -> None:
        nonlocal size
        if size > limit:
            return
        if isinstance(v, str):
            out.append(v)
            size += len(v)
        elif isinstance(v, dict):
            for k, item in v.items():
                walk(str(k))
                walk(item)
        elif isinstance(v, list | tuple):
            for item in v:
                walk(item)
        elif v is not None:
            out.append(str(v))

    walk(value)
    return "\n".join(out)[:limit]


def extract_indicators(text: str, extra_urls: Iterable[str] = (), ignore_hosts: Iterable[str] = ()) -> Indicators:
    ignore = {h.lower() for h in ignore_hosts}
    urls = sorted({u.rstrip(".,);") for u in [*_URL_RE.findall(text), *extra_urls] if u})
    ips: set[str] = set()
    for candidate in _IP_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
            ips.add(candidate)
        except ValueError:
            continue
    domains = {d.lower() for d in _DOMAIN_RE.findall(text)}
    for u in urls:
        m = re.match(r"^[a-z0-9]+://([^/:?#]+)", u, re.IGNORECASE)
        if m:
            domains.add(m.group(1).lower())
    domains -= ignore
    urls = [u for u in urls if not any(h in u.lower() for h in ignore)]
    markers = sorted({m.group(0) for rx in _INJECTION_RE for m in [rx.search(text)] if m})
    return Indicators(
        urls=urls,
        domains=sorted(domains),
        ips=sorted(ips),
        emails=sorted(set(_EMAIL_RE.findall(text))),
        prompt_injection_markers=markers,
    )


def fingerprint(
    client_info: dict[str, Any] | None,
    protocol_version: str | None,
    user_agent: str | None,
    capabilities: dict[str, Any] | None,
    history: list[float] | None = None,
    prose_args: bool = False,
) -> AgentFingerprint:
    """Classify the caller. Signals are recorded so analysts can see *why*."""
    # Every field here is attacker-controlled: clip it before it reaches any sink.
    info = client_info if isinstance(client_info, dict) else {}
    name = str(info.get("name") or "")[:128]
    version = str(info.get("version") or "")[:64] or None
    user_agent = user_agent[:256] if user_agent else user_agent
    protocol_version = str(protocol_version)[:32] if protocol_version else None
    capabilities = capabilities if isinstance(capabilities, dict) else {}
    ua = (user_agent or "").lower()
    lname = name.lower()
    signals: list[str] = []
    scores = {"ai_agent": 0.0, "mcp_client": 0.0, "scanner": 0.0, "script": 0.0}

    if name:
        signals.append(f"clientInfo.name={name}")
        if any(k in lname for k in _AI_CLIENTS):
            scores["ai_agent"] += 0.6
            signals.append("known AI agent host")
        elif any(k in lname for k in _DEV_CLIENTS):
            scores["mcp_client"] += 0.5
            signals.append("known MCP developer tool")
        else:
            scores["mcp_client"] += 0.3
    else:
        scores["script"] += 0.3
        signals.append("no clientInfo")
    if any(k in ua for k in _SCANNERS) or any(k in lname for k in _SCANNERS):
        scores["scanner"] += 0.8
        signals.append("scanner user-agent")
    elif any(k in ua for k in _SCRIPTS):
        scores["script"] += 0.4
        signals.append(f"scripted user-agent ({ua[:40]})")
    caps = sorted(str(k)[:32] for k in list(capabilities.keys())[:16])
    if {"sampling", "elicitation", "roots"} & set(caps):
        scores["ai_agent"] += 0.2
        signals.append("advertises agent capabilities (" + ",".join(caps) + ")")
    if prose_args:
        scores["ai_agent"] += 0.25
        signals.append("natural-language justification in arguments")
    if history and len(history) >= 2:
        # ``history`` holds think-times: seconds between our response and the next request.
        avg = sum(history) / len(history)
        if avg < 0.25:
            scores["script"] += 0.3
            signals.append(f"machine-speed follow-ups (avg think time {avg * 1000:.0f} ms)")
        elif 0.8 < avg < 60:
            scores["ai_agent"] += 0.2
            signals.append(f"LLM-paced follow-ups (avg think time {avg:.1f} s)")
    label, best = max(scores.items(), key=lambda kv: kv[1])
    classification = label if best >= 0.3 else "unknown"
    return AgentFingerprint(
        client_name=name or None,
        client_version=version,
        protocol_version=protocol_version,
        user_agent=user_agent,
        capabilities=caps,
        classification=classification,  # type: ignore[arg-type]
        confidence=round(min(best, 1.0), 2),
        signals=signals,
    )


def looks_like_prose(arguments: dict[str, Any] | None) -> bool:
    if not arguments:
        return False
    for v in arguments.values():
        if isinstance(v, str) and len(v.split()) >= 5 and re.search(r"[a-z]{3,}\s+[a-z]{3,}", v):
            return True
    return False


def max_severity(*levels: Severity | str | None) -> Severity:
    valid = [str(lv) for lv in levels if lv in SEVERITY_RANK]
    if not valid:
        return "info"
    return cast(Severity, max(valid, key=lambda lv: SEVERITY_RANK[lv]))


RECON_ATTACK = {
    "tools/list": ["T1526"],
    "resources/list": ["T1083"],
    "prompts/list": ["T1526"],
    "server/discover": ["T1046"],
    "initialize": ["T1046"],
}
