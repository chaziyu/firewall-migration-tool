from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGDHCPIPRange(BaseModel):
    id: int | None = None

    start_ip: str | None = None
    end_ip: str | None = None
    lease_time: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGDHCPExcludeRange(BaseModel):
    id: int | None = None

    start_ip: str | None = None
    end_ip: str | None = None
    lease_time: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGDHCPReservedAddress(BaseModel):
    id: int | None = None

    ip: str | None = None
    mac: str | None = None
    description: str | None = None

    action: str | None = None
    type: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGDHCPServer(BaseModel):
    id: int | None = None
    vdom: str = "root"

    # Direct interface relationship.
    interface: str | None = None

    status: str | None = None
    server_type: str | None = None
    ip_mode: str | None = None

    # Core network settings.
    default_gateway: str | None = None
    netmask: str | None = None
    lease_time: int | None = None

    # DNS remains in source shape.
    dns_service: str | None = None
    dns_server1: str | None = None
    dns_server2: str | None = None
    dns_server3: str | None = None
    dns_server4: str | None = None

    # Timezone.
    timezone_option: str | None = None
    timezone: str | None = None

    # Relay.
    relay_agent: str | None = None

    # Nested source objects.
    ip_ranges: list[FGDHCPIPRange] = Field(default_factory=list)
    exclude_ranges: list[FGDHCPExcludeRange] = Field(default_factory=list)
    reserved_addresses: list[FGDHCPReservedAddress] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)