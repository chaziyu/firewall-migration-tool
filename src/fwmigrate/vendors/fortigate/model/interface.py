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


class FGInterface(BaseModel):
    """
    Small FortiGate source interface model.

    Only explicit migration-relevant source data belongs here.
    Relationship ancestry is resolved later.
    """

    name: str
    vdom: str = "root"

    # Source identity / presentation
    alias: str | None = None
    description: str | None = None

    # Source interface characteristics
    type: str | None = None
    role: str | None = None
    mode: str | None = None
    status: str | None = None

    # Addressing
    ip: str | None = None
    secondary_ips: list[FGInterfaceSecondaryIP] = Field(
        default_factory=list
    )

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