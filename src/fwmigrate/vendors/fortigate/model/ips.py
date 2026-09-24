from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGIPSExemptIP(BaseModel):
    id: int | None = None

    src_ip: str | None = None
    dst_ip: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGIPSSensorEntry(BaseModel):
    id: int | None = None

    # Signature selection / filtering
    rule: list[int] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)

    application: str | None = None
    os: str | None = None
    protocol: str | None = None
    severity: str | None = None
    location: str | None = None

    vuln_type: list[int] = Field(default_factory=list)

    # Source/default matching
    default_action: str | None = None
    default_status: str | None = None

    # Configured/source action and status
    action: str | None = None
    status: str | None = None

    # Logging
    log: str | None = None
    log_packet: str | None = None
    log_attack_context: str | None = None

    # Quarantine / rate behavior
    quarantine: str | None = None
    quarantine_expiry: str | None = None
    quarantine_log: str | None = None

    rate_count: int | None = None
    rate_duration: int | None = None
    rate_mode: str | None = None
    rate_track: str | None = None

    # Source metadata / filtering
    last_modified: str | None = None

    # Nested exemptions
    exempt_ips: list[FGIPSExemptIP] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGIPSSensor(BaseModel):
    name: str
    vdom: str = "root"

    # Main sensor settings
    comment: str | None = None
    block_malicious_url: str | None = None
    scan_botnet_connections: str | None = None

    # Logging / response
    extended_log: str | None = None
    replacemsg_group: str | None = None

    # Nested IPS filters / signatures
    entries: list[FGIPSSensorEntry] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
