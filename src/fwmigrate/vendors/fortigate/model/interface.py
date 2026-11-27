from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGInterfaceSecondaryIP(BaseModel):
    id: int | None = None

    ip: str | None = None
    allowaccess: list[str] = Field(default_factory=list)
    ha_priority: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGInterfaceIPv6(BaseModel):
    ip6_mode: str | None = None
    ip6_address: str | None = None
    ip6_allowaccess: list[str] = Field(default_factory=list)
    ip6_send_adv: str | None = None
    ip6_manage_flag: str | None = None
    ip6_other_flag: str | None = None
    ip6_default_life: int | None = None
    ip6_dns_server_override: str | None = None
    dhcp6_prefix_delegation: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGInterface(BaseModel):
    """
    Small FortiGate source interface model.

    Only explicit migration-relevant source data belongs here.
    Relationship ancestry is resolved later.
    """

    name: str
    vdom: str | None = "root"
    cli_vdom: str | None = "root"
    cli_scope: str = "vdom"
    unset_fields: set[str] = Field(default_factory=set)

    # Source identity / presentation
    alias: str | None = None
    description: str | None = None

    # Source interface characteristics
    type: str | None = None
    role: str | None = None
    dedicated_to: str | None = None
    mode: str | None = None
    status: str | None = None
    mtu_override: str | None = None
    dhcp_relay_service: str | None = None

    # Addressing
    ip: str | None = None
    secondary_ips: list[FGInterfaceSecondaryIP] = Field(
        default_factory=list
    )
    ipv6: FGInterfaceIPv6 | None = None

    # Administrative access
    allowaccess: list[str] = Field(default_factory=list)

    # Direct FortiGate parent relationship.
    #
    # Examples:
    #   VLAN:
    #       set interface "port1"
    #
    #   VLAN over aggregate:
    #       set interface "agg1"
    interface: str | None = None

    vlanid: int | None = None

    # Aggregate/redundant source membership.
    #
    # Example:
    #   edit "agg1"
    #       set type aggregate
    #       set member "port1" "port2"
    members: list[str] = Field(default_factory=list)

    # Network context
    vrf: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
