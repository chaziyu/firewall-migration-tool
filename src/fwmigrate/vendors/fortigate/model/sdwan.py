from typing import Any

from pydantic import BaseModel, Field


class FGSDWANZone(BaseModel):
    name: str

    minimum_sla_meet_members: int | None = None

    raw_extra: dict[str, Any] = Field(
        default_factory=dict
    )
    explicit_fields: set[str] = Field(
        default_factory=set
    )


class FGSDWANMember(BaseModel):
    seq_num: int | None = None

    # Direct source relationships.
    interface: str | None = None
    zone: str | None = None

    gateway: str | None = None
    source: str | None = None

    priority: int | None = None
    cost: int | None = None
    weight: int | None = None

    status: str | None = None

    raw_extra: dict[str, Any] = Field(
        default_factory=dict
    )
    explicit_fields: set[str] = Field(
        default_factory=set
    )


class FGSDWANHealthCheck(BaseModel):
    name: str

    protocol: str | None = None
    server: str | None = None

    # References SD-WAN member sequence numbers.
    members: list[int] = Field(
        default_factory=list
    )

    interval: int | None = None
    failtime: int | None = None
    recoverytime: int | None = None

    raw_extra: dict[str, Any] = Field(
        default_factory=dict
    )
    explicit_fields: set[str] = Field(
        default_factory=set
    )


class FGSDWANService(BaseModel):
    id: int | None = None

    name: str | None = None
    mode: str | None = None
    status: str | None = None

    src: list[str] = Field(
        default_factory=list
    )
    dst: list[str] = Field(
        default_factory=list
    )

    # References SD-WAN member sequence numbers.
    priority_members: list[int] = Field(
        default_factory=list
    )

    # References SD-WAN zone names.
    priority_zone: list[str] = Field(
        default_factory=list
    )

    # References SD-WAN health-check names.
    health_check: list[str] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(
        default_factory=dict
    )
    explicit_fields: set[str] = Field(
        default_factory=set
    )


class FGSDWAN(BaseModel):
    vdom: str = "root"

    status: str | None = None
    load_balance_mode: str | None = None

    zones: list[FGSDWANZone] = Field(
        default_factory=list
    )
    members: list[FGSDWANMember] = Field(
        default_factory=list
    )
    health_checks: list[FGSDWANHealthCheck] = Field(
        default_factory=list
    )
    services: list[FGSDWANService] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(
        default_factory=dict
    )
    explicit_fields: set[str] = Field(
        default_factory=set
    )