"""Shared public IP classification and local-only TCP/TLS/SSH exposure probing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network, ip_address
from re import compile as re_compile
from socket import create_connection, socket as SocketType, timeout as SocketTimeout
from ssl import CERT_NONE, PROTOCOL_TLS_CLIENT, SSLContext
from typing import Any, Callable

HIGH_RISK_VIP_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
}
CRITICAL_VIP_PORTS: frozenset[int] = frozenset({22, 23, 80, 445, 1433, 3306, 3389, 5432, 5900})

_CGNAT_NET = IPv4Network("100.64.0.0/10")
_TREE_PREFIX_RE = re_compile(r"^[\s\u00a0]*(?:\u2517|\u2514)?[\s\u00a0]*")


def clean_interface_name(name: str | None) -> str:
    return _TREE_PREFIX_RE.sub("", str(name or "")).strip()


def bare_ip(ip_str: str | None) -> str:
    """Strip CIDR/netmask and optional IPv4:port suffix from an address string."""
    raw = str(ip_str or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0].strip()
    if " " in raw:
        raw = raw.split(" ", 1)[0].strip()
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0].strip()
    return raw


def is_public_ip(ip_str: str | None) -> bool:
    """Return True if ip_str is a routable public IP (excluding RFC1918, CGNAT, loopback, etc.)."""
    if not ip_str:
        return False
    raw = str(ip_str).strip()
    if not raw or raw.lower() in {"-", "none", "dhcp", "pppoe", "unknown"}:
        return False
    addr_part = bare_ip(raw)
    if not addr_part:
        return False
    try:
        addr = ip_address(addr_part)
    except ValueError:
        return False
    if isinstance(addr, IPv4Address) and addr in _CGNAT_NET:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    return bool(addr.is_global)


def extract_public_ips(ip_field: str | None) -> list[str]:
    """Return all public IP tokens from a comma-separated interface IP field."""
    if not ip_field:
        return []
    out: list[str] = []
    for part in str(ip_field).split(","):
        candidate = part.strip()
        if is_public_ip(candidate):
            out.append(candidate)
    return out


def build_exposure_targets(
    public_ips: list[str],
    protocols: list[str],
    port_map: dict[str, int],
) -> list[dict[str, Any]]:
    """Build concrete (ip, port, protocol) targets for optional local reachability probing."""
    targets: list[dict[str, Any]] = []
    for raw_ip in public_ips:
        addr = bare_ip(raw_ip)
        if not is_public_ip(addr):
            continue
        for proto in protocols:
            port = port_map.get(proto)
            if port:
                targets.append({"ip": addr, "port": int(port), "protocol": proto})
    return targets


def _read_ssh_banner(conn: Any, timeout: float) -> str | None:
    if not hasattr(conn, "recv"):
        return None
    try:
        if hasattr(conn, "settimeout"):
            conn.settimeout(min(2.0, timeout))
        raw = conn.recv(256)
        if not raw:
            return None
        first_line = raw.decode("utf-8", errors="ignore").splitlines()[0]
        cleaned = "".join(ch for ch in first_line if 32 <= ord(ch) <= 126).strip()
        if cleaned.startswith("SSH-"):
            return cleaned[:64]
    except Exception:
        return None
    return None


def _read_tls_version(conn: Any, ip: str, timeout: float) -> str | None:
    if not isinstance(conn, SocketType):
        return None
    try:
        ctx = SSLContext(PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = CERT_NONE
        conn.settimeout(min(5.0, timeout))
        with ctx.wrap_socket(conn, server_hostname=ip) as tls_sock:
            return tls_sock.version()
    except Exception:
        return None


def _probe_one(
    task: tuple[str, str, int, str, str, bool],
    timeout: float,
    connect_fn: Callable[[tuple[str, int], float], Any],
) -> dict[str, Any]:
    iface, ip, port, proto, cfg_sev, restricted = task
    try:
        conn = connect_fn((ip, port), timeout)
        status = "open"
        detail = "TCP Open (Verified Reachable)"
        try:
            if proto == "SSH":
                banner = _read_ssh_banner(conn, timeout)
                if banner:
                    detail = f"TCP Open — SSH Banner: {banner}"
            elif proto == "HTTPS":
                tls_ver = _read_tls_version(conn, ip, timeout)
                if tls_ver:
                    detail = f"TCP Open — {tls_ver} Handshake OK"
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except ConnectionRefusedError:
        status = "refused"
        detail = "Connection Refused (from this host)"
    except (TimeoutError, SocketTimeout, OSError):
        status = "filtered"
        detail = "Filtered / Timed Out (from this host)"

    if cfg_sev == "critical":
        sev_label = "Critical"
    elif restricted:
        sev_label = "Warning (Restricted)"
    else:
        sev_label = "Warning"

    return {
        "interface": iface,
        "ip": ip,
        "port": port,
        "protocol": proto,
        "config_severity": sev_label,
        "status": status,
        "detail": detail,
    }


def probe_exposure_targets(
    findings: list[dict[str, Any]],
    *,
    timeout: float = 5.0,
    connect_fn: Callable[[tuple[str, int], float], Any] | None = None,
) -> dict[str, Any]:
    """Perform bounded TCP connect probes strictly against public targets derived from exposure findings."""
    tasks: list[tuple[str, str, int, str, str, bool]] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        iface = str(finding.get("interface", "-"))
        cfg_sev = str(finding.get("severity", "warn"))
        restricted = bool(finding.get("restricted", False))
        for target in finding.get("targets") or ():
            ip = bare_ip(str(target.get("ip", "")))
            port = int(target.get("port", 0) or 0)
            proto = str(target.get("protocol", ""))
            if not is_public_ip(ip) or port <= 0:
                continue
            key = (iface, ip, port)
            if key in seen:
                continue
            seen.add(key)
            tasks.append((iface, ip, port, proto, cfg_sev, restricted))

    if not tasks:
        return {"open_count": 0, "total": 0, "results": []}

    dial = connect_fn or (lambda addr, t: create_connection(addr, timeout=t))
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        results = list(pool.map(lambda task: _probe_one(task, timeout, dial), tasks))
    open_count = sum(1 for row in results if row["status"] == "open")
    return {
        "open_count": open_count,
        "total": len(results),
        "results": results,
    }
