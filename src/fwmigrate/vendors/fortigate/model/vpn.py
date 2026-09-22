from typing import Any

from pydantic import BaseModel, Field


class FGIPsecPhase1(BaseModel):
    name: str
    vdom: str = "root"

    # Tunnel / gateway type
    type: str | None = None

    # Local attachment
    interface: str | None = None
    local_gw: str | None = None

    # Remote peer
    remote_gw: str | None = None
    remotegw_ddns: str | None = None

    # IKE
    ike_version: str | None = None
    mode: str | None = None
    authmethod: str | None = None
    authmethod_remote: str | None = None
    proposal: list[str] = Field(default_factory=list)
    dhgrp: list[int] = Field(default_factory=list)

    # Phase 1 lifetime
    keylife: int | None = None

    # NAT traversal / liveness
    nattraversal: str | None = None
    dpd: str | None = None
    dpd_retrycount: int | None = None
    dpd_retryinterval: str | None = None

    # Optional identity/certificate references
    localid: str | None = None
    localid_type: str | None = None
    peerid: str | None = None
    certificate: list[str] = Field(default_factory=list)

    # Credential presence metadata; the credential itself is never retained.
    psk_configured: bool = False

    # Metadata
    comments: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGIPsecPhase2(BaseModel):
    name: str
    vdom: str = "root"

    # Link to Phase 1
    phase1name: str | None = None

    # Phase 2 crypto
    proposal: list[str] = Field(default_factory=list)
    pfs: str | None = None
    dhgrp: list[int] = Field(default_factory=list)

    # Lifetime
    keylifeseconds: int | None = None
    keylifekbs: int | None = None

    # Source selector
    src_addr_type: str | None = None
    src_subnet: str | None = None
    src_start_ip: str | None = None
    src_end_ip: str | None = None
    src_name: str | None = None

    # Destination selector
    dst_addr_type: str | None = None
    dst_subnet: str | None = None
    dst_start_ip: str | None = None
    dst_end_ip: str | None = None
    dst_name: str | None = None

    # Tunnel behavior
    replay: str | None = None
    auto_negotiate: str | None = None

    # Metadata
    comments: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
