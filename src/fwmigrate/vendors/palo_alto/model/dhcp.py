from __future__ import annotations

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANDHCPIPPool(PANNestedSourceModel):
    name: str | None = None
    value: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None


class PANDHCPReservation(PANNestedSourceModel):
    name: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    description: str | None = None


class PANDHCPOption(PANNestedSourceModel):
    name: str | None = None
    code: str | None = None
    vendor_class_identifier: str | None = None
    inherited: str | None = None
    value_type: str | None = None
    ip_values: list[str] | None = None
    ascii_values: list[str] | None = None
    hex_values: list[str] | None = None


class PANDHCPServer(PANNamedSourceModel):
    interface: str | None = None
    mode: str | None = None
    probe_ip: str | None = None
    lease_type: str | None = None
    lease_timeout: str | None = None
    inheritance_source: str | None = None
    gateway: str | None = None
    subnet_mask: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    wins: list[str] | None = None
    ntp: list[str] | None = None
    pop3_server: str | None = None
    smtp_server: str | None = None
    dns_suffix: str | None = None
    ip_pools: list[PANDHCPIPPool] | None = None
    reservations: list[PANDHCPReservation] | None = None
    options: list[PANDHCPOption] | None = None
