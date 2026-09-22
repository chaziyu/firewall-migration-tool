from __future__ import annotations

from pydantic import BaseModel, Field

from ..source_model import PANScope, PANSourceRecord
from .address import PANAddress, PANAddressGroup
from .interface import PANInterface, PANInterfaceImport, PANInterfaceUnit
from .nat import PANNATRule
from .policy import PANDefaultSecurityRule, PANSecurityRule
from .routing import PANLogicalRouter, PANStaticRoute, PANVirtualRouter
from .schedule import PANSchedule
from .service import PANService, PANServiceGroup


class PANOSConfig(BaseModel):
    """Typed, explicit PAN-OS source state plus source inventory evidence."""

    hostname: str | None = None
    source_version: str | None = None
    source_format: str = "xml"
    scopes: list[PANScope] = Field(default_factory=list)

    addresses: list[PANAddress] = Field(default_factory=list)
    address_groups: list[PANAddressGroup] = Field(default_factory=list)
    services: list[PANService] = Field(default_factory=list)
    service_groups: list[PANServiceGroup] = Field(default_factory=list)
    schedules: list[PANSchedule] = Field(default_factory=list)
    security_rules: list[PANSecurityRule] = Field(default_factory=list)
    default_security_rules: list[PANDefaultSecurityRule] = Field(default_factory=list)
    interfaces: list[PANInterface] = Field(default_factory=list)
    interface_imports: list[PANInterfaceImport] = Field(default_factory=list)
    interface_units: list[PANInterfaceUnit] = Field(default_factory=list)
    nat_rules: list[PANNATRule] = Field(default_factory=list)
    static_routes: list[PANStaticRoute] = Field(default_factory=list)
    virtual_routers: list[PANVirtualRouter] = Field(default_factory=list)
    logical_routers: list[PANLogicalRouter] = Field(default_factory=list)

    source_inventory: list[PANSourceRecord] = Field(default_factory=list)
    unknown_paths: list[str] = Field(default_factory=list)
