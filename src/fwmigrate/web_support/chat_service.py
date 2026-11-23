"""Session-scoped RAM chat state and Gemini AI firewall configuration assistant."""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
MAX_SUMMARY_CHARS = 250_000
TEMPERATURE = 0.1
MAX_OUTPUT_TOKENS = 2048
SESSION_TTL_SECONDS = 2 * 3600
MAX_SESSIONS = 32
ROOT_DIR = Path(__file__).resolve().parents[3]


@dataclass
class ChatSession:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    gemini_api_key: str | None = None
    chat_history: list[dict[str, str]] = field(default_factory=list)
    config_summary: str | None = None
    config_digest: str | None = None
    vendor: str | None = None
    filename: str | None = None
    vendor_mismatch: str | None = None


class ChatSessionStore:
    """In-memory bounded session store (RAM-only; API keys and chat logs are never written to disk)."""

    def __init__(self, *, max_sessions: int = MAX_SESSIONS, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._sessions: OrderedDict[str, ChatSession] = OrderedDict()
        self._lock = threading.Lock()
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds

    def _prune(self, now: float) -> None:
        expired = [
            sid for sid, sess in self._sessions.items()
            if now - sess.last_accessed > self._ttl_seconds
        ]
        for sid in expired:
            self._sessions.pop(sid, None)
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)

    def get(self, session_id: str | None) -> ChatSession | None:
        if not session_id:
            return None
        with self._lock:
            now = time.time()
            self._prune(now)
            sess = self._sessions.get(session_id)
            if sess is not None:
                sess.last_accessed = now
                self._sessions.move_to_end(session_id)
            return sess

    def get_or_create(self, session_id: str | None) -> tuple[ChatSession, bool]:
        with self._lock:
            now = time.time()
            self._prune(now)
            if session_id and session_id in self._sessions:
                sess = self._sessions[session_id]
                sess.last_accessed = now
                self._sessions.move_to_end(session_id)
                return sess, False
            new_id = secrets.token_urlsafe(24)
            sess = ChatSession(session_id=new_id, created_at=now, last_accessed=now)
            self._sessions[new_id] = sess
            self._prune(now)
            return sess, True


chat_store = ChatSessionStore()


def detect_vendor_from_content(raw_text: str) -> str | None:
    if not raw_text:
        return None
    sample = raw_text[:6000]
    looks_xml = bool(re.search(r"<\?xml|<config[\s>]|<entry\s+name=", sample, re.IGNORECASE))
    looks_fortios = bool(
        re.search(r"^\s*config\s+(system|firewall|router|log|user|vpn|wireless)", sample, re.IGNORECASE | re.MULTILINE)
    )
    looks_asa = bool(
        re.search(r"^\s*(?:ASA Version|access-list\s+\S+\s+extended|object\s+(?:network|service)\s+)", sample, re.IGNORECASE | re.MULTILINE)
    )
    looks_srx = bool(
        re.search(r"^\s*(?:security\s*\{|set\s+security\s+(?:policies|zones|nat))", sample, re.IGNORECASE | re.MULTILINE)
    )
    if looks_xml and not looks_fortios and not looks_asa and not looks_srx:
        return "palo_alto"
    if looks_fortios and not looks_xml:
        return "fortigate"
    if looks_asa and not looks_xml and not looks_fortios:
        return "cisco_asa"
    if looks_srx and not looks_xml and not looks_fortios:
        return "juniper_srx"
    return None


def _fmt_rows(rows: list[Any], max_rows: int = 120) -> list[str]:
    out = []
    for row in rows[:max_rows]:
        if isinstance(row, dict):
            parts = []
            for k, v in row.items():
                if k in {"raw_extra", "additional_settings", "explicit_fields", "source_identity"}:
                    continue
                if v in (None, "", [], {}):
                    continue
                if isinstance(v, list):
                    rendered = ", ".join(str(x) for x in v[:12])
                    if len(v) > 12:
                        rendered += f", ... (+{len(v) - 12})"
                elif isinstance(v, dict):
                    rendered = json.dumps(v, ensure_ascii=False)[:180]
                else:
                    rendered = str(v)
                parts.append(f"{k}={rendered}")
            if parts:
                out.append("  - " + " | ".join(parts))
        else:
            out.append(f"  - {row}")
    if len(rows) > max_rows:
        out.append(f"  ... and {len(rows) - max_rows} more entries omitted for brevity")
    return out


def build_config_summary(
    *,
    vendor: str,
    filename: str,
    preview: dict[str, Any] | None = None,
    source_text: str | None = None,
) -> str:
    out: list[str] = [f"=== {vendor} Config Summary ({filename}) ==="]
    summary = (preview or {}).get("summary") or {}
    if summary:
        hostname = preview.get("hostname") or summary.get("hostname") or summary.get("source_metadata", {}).get("hostname")
        version = preview.get("source_version") or summary.get("source_version") or summary.get("source_metadata", {}).get("fortios_version")
        if hostname:
            out.append(f"Hostname: {hostname}")
        if version:
            out.append(f"Version: {version}")
        vdoms = summary.get("vdoms") or summary.get("scopes")
        if vdoms:
            out.append(f"Scopes / VDOMs: {', '.join(map(str, vdoms))}")
        counts = summary.get("objects")
        if isinstance(counts, dict) and counts:
            non_zero = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
            if non_zero:
                out.append(f"Object counts: {non_zero}")

    sections = (preview or {}).get("sections") or {}
    if isinstance(sections, dict):
        priority_order = (
            "interfaces", "interface_topology", "zones", "routes", "virtual_routers", "logical_routers",
            "router_bgp", "router_ospf", "policy_routes", "policies", "security_rules", "default_security_rules",
            "proxy_policies", "auth_policies", "qos_rules", "pbf_rules", "decryption_rules",
            "nat", "nat_rules", "central_snat", "vips", "ip_pools",
            "addresses", "address_groups", "services", "service_groups", "schedules",
            "vpn_tunnels", "vpn_phase2", "ipsec_tunnels", "ike_gateways", "ssl_vpn_settings", "globalprotect_portals", "globalprotect_gateways",
            "profile_groups", "security_profile_groups", "ips_sensors", "vulnerability_profiles",
            "antivirus_profiles", "anti_spyware_profiles", "webfilter_profiles", "url_filtering_profiles", "ssl_ssh_profiles",
            "administrators", "local_users", "user_groups", "ldap_servers", "radius_servers",
            "system_global", "system_settings", "ha_config", "ha_configs", "validation", "unresolved_references",
        )
        seen: set[str] = set()
        for key in (*priority_order, *sections.keys()):
            if key in seen or key in {"source_inventory", "extraction_coverage"}:
                continue
            seen.add(key)
            val = sections.get(key)
            if isinstance(val, list) and val:
                cap = 400 if key in {"policies", "security_rules", "addresses", "routes"} else 150
                out.append(f"\n[{key}] — {len(val)} entries")
                out.extend(_fmt_rows(val, max_rows=cap))
            elif isinstance(val, dict) and val:
                out.append(f"\n[{key}]")
                out.extend(_fmt_rows([val], max_rows=20))

    unresolved = (preview or {}).get("unresolved_references")
    if isinstance(unresolved, list) and unresolved:
        out.append(f"\n[unresolved_references] — {len(unresolved)} entries")
        out.extend(_fmt_rows(unresolved, max_rows=100))

    if len(out) <= 1 and source_text:
        out.append("\n=== Raw config (truncated) ===\n" + source_text[:MAX_SUMMARY_CHARS])

    joined = "\n".join(out)
    if len(joined) > MAX_SUMMARY_CHARS:
        joined = joined[:MAX_SUMMARY_CHARS] + "\n... [summary truncated to fit context budget]"
    return joined


def _resolve_api_key(session_key: str | None = None, *, allow_env_fallback: bool = True) -> tuple[str | None, str | None]:
    if session_key and session_key.strip():
        return session_key.strip(), "session"
    if not allow_env_fallback:
        return None, None
    env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip(), "local-env"
    secrets_toml = ROOT_DIR / ".streamlit" / "secrets.toml"
    if secrets_toml.exists():
        try:
            data = tomllib.loads(secrets_toml.read_text(encoding="utf-8"))
            val = data.get("GEMINI_API_KEY") or data.get("GOOGLE_API_KEY")
            if val and str(val).strip():
                return str(val).strip(), "local-secrets"
        except Exception:
            pass
    dotenv = ROOT_DIR / ".env"
    if dotenv.exists():
        try:
            for line in dotenv.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith(("GEMINI_API_KEY=", "GOOGLE_API_KEY=")):
                    val = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val, "local-.env"
        except Exception:
            pass
    return None, None


def get_api_key_status(session_key: str | None = None, *, allow_env_fallback: bool = True) -> dict[str, Any]:
    key, source = _resolve_api_key(session_key, allow_env_fallback=allow_env_fallback)
    if not key:
        return {"configured": False, "source": None, "masked": None}
    masked = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "****"
    return {"configured": True, "source": source, "masked": masked}


def build_system_prompt(
    *,
    config_summary: str,
    vendor: str,
    filename: str,
    vendor_mismatch: str | None = None,
) -> str:
    mismatch_note = ""
    if vendor_mismatch and vendor_mismatch != vendor:
        mismatch_note = (
            f"\nIMPORTANT: File selection indicated {vendor}, while config content looks like {vendor_mismatch}. "
            "Mention this discrepancy if relevant.\n"
        )
    return (
        "You are a senior network security and firewall migration assistant embedded in Firewall Migration Tool.\n\n"
        f'The user has loaded a {vendor} configuration file named "{filename}".\n'
        "Available workflow views: Configuration Report (Overview, Interfaces, Objects, Schedules, Policies, NAT, Routes, VPN, References, Extraction) "
        "and Plan Migration.\n"
        f"{mismatch_note}\n"
        "Guidelines:\n"
        "1. Grounding: Answer ONLY using the provided configuration summary below. Never invent rules, IPs, interfaces, or objects not present.\n"
        "2. Truncation Awareness: If a section notes '... and N more entries omitted for brevity' or the summary is truncated, "
        "state that clearly and direct the user to the corresponding report tab or Excel export.\n"
        "3. Firewall Semantics: Evaluate policies using top-down first-match ordering and implicit deny, accounting for zones/interfaces, "
        "address/service groups, NAT/VIPs, security profiles, validation findings, and unresolved references.\n"
        "4. Formatting: Be concise, accurate, and technical. Use Markdown: wrap identifiers/IPs in `inline code`, use **bold** for key verdicts, "
        "and bullet lists for breakdowns.\n\n"
        f"=== CONFIG SUMMARY ===\n{config_summary}\n=== END CONFIG SUMMARY ==="
    )


def _call_gemini_rest(
    *,
    api_key: str,
    system_prompt: str,
    contents: list[dict[str, Any]],
    model: str = MODEL,
    timeout: float = 45.0,
) -> str:
    encoded_model = urllib.parse.quote(model, safe="")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{encoded_model}:generateContent?key={urllib.parse.quote(api_key, safe='')}"
    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {
            "temperature": TEMPERATURE,
            "maxOutputTokens": MAX_OUTPUT_TOKENS,
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    candidates = body.get("candidates") or []
    if not candidates:
        return ""
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    return "\n".join(str(part.get("text") or "") for part in parts if part.get("text")).strip()


def _call_gemini_sdk(
    *,
    api_key: str,
    system_prompt: str,
    contents: list[dict[str, Any]],
    model: str = MODEL,
) -> str | None:
    try:
        from google import genai
        from google.genai import types as genai_types
    except ImportError:
        return None
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=contents,
        config=genai_types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=TEMPERATURE,
            max_output_tokens=MAX_OUTPUT_TOKENS,
        ),
    )
    return (response.text or "").strip()


def _call_gemini(
    *,
    api_key: str,
    system_prompt: str,
    contents: list[dict[str, Any]],
) -> str:
    sdk_text = _call_gemini_sdk(api_key=api_key, system_prompt=system_prompt, contents=contents)
    if sdk_text is not None:
        return sdk_text
    return _call_gemini_rest(api_key=api_key, system_prompt=system_prompt, contents=contents)


def ask_gemini(
    *,
    question: str,
    config_summary: str,
    vendor: str,
    filename: str,
    chat_history: list[dict[str, str]],
    vendor_mismatch: str | None = None,
    api_key_override: str | None = None,
    allow_env_fallback: bool = True,
) -> tuple[bool, str]:
    """Return (success, reply_or_error_message)."""
    api_key, _ = _resolve_api_key(api_key_override, allow_env_fallback=allow_env_fallback)
    if not api_key:
        return (
            False,
            "⚠️ No Gemini API key configured for this session. Click the 🔑 key button in the chat header to enter your Gemini API key.",
        )

    system_prompt = build_system_prompt(
        config_summary=config_summary,
        vendor=vendor,
        filename=filename,
        vendor_mismatch=vendor_mismatch,
    )
    contents = []
    for item in chat_history[-10:]:
        role = "model" if item.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": str(item.get("content") or "")}]})
    contents.append({"role": "user", "parts": [{"text": question}]})

    try:
        text = _call_gemini(api_key=api_key, system_prompt=system_prompt, contents=contents)
        if not text:
            return False, "⚠️ Gemini returned an empty response."
        return True, text
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            err_body = json.loads(exc.read().decode("utf-8", errors="replace"))
            detail = str((err_body.get("error") or {}).get("message") or "")
        except Exception:
            pass
        return False, f"⚠️ Gemini API error (HTTP {exc.code}){f': {detail}' if detail else ''}"
    except Exception as exc:
        return False, f"⚠️ Error contacting Gemini: {exc}"
