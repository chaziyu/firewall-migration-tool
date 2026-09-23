"""Cisco ASA configuration collection over SSH."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CollectedSource:
    vendor_id: str
    source_text: str
    source_name: str
    metadata: dict[str, Any]


def _connect(options):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError("Live collection requires the deployment extra (netmiko).") from exc
    return ConnectHandler(
        device_type="cisco_asa", host=options["host"], port=options["port"],
        username=options["username"], password=options["password"],
        conn_timeout=15, auth_timeout=15, banner_timeout=15,
    )


def test_connection(options):
    connection = _connect(options)
    connection.disconnect()


def collect(options) -> CollectedSource:
    connection = _connect(options)
    try:
        content = connection.send_command("show running-config", read_timeout=60)
    finally:
        connection.disconnect()
    if not content.strip():
        raise RuntimeError("The device returned an empty configuration.")
    return CollectedSource("cisco_asa", content, "live-cisco-asa.cfg", {"method": "ssh"})
