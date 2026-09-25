from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGNACPolicy(BaseModel):
    name: str
    vdom: str = "root"
    category: str | None = None
    description: str | None = None
    ems_tag: str | None = None
    family: str | None = None
    firewall_address: str | None = None
    fortivoice_tag: str | None = None
    host: str | None = None
    hw_vendor: str | None = None
    hw_version: str | None = None
    mac: str | None = None
    match_period: int | None = None
    match_type: str | None = None
    os: str | None = None
    severity: list[int] = Field(default_factory=list)
    src: str | None = None
    ssid_policy: str | None = None
    status: str | None = None
    sw_version: str | None = None
    switch_fortilink: str | None = None
    switch_group: list[str] = Field(default_factory=list)
    switch_mac_policy: str | None = None
    type: str | None = None
    user: str | None = None
    user_group: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6TemplateValue(BaseModel):
    name: str
    value: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6TemplateSegment(BaseModel):
    id: int | None = None
    bits: int | None = None
    exclusive: str | None = None
    name: str | None = None
    values: list[FGAddress6TemplateValue] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6Template(BaseModel):
    name: str
    vdom: str = "root"
    fabric_object: str | None = None
    ip6: str | None = None
    subnet_segment_count: int | None = None
    segments: list[FGAddress6TemplateSegment] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGIPSSettings(BaseModel):
    vdom: str = "root"
    ips_packet_quota: int | None = None
    packet_log_history: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKMIPServerEntry(BaseModel):
    id: int | None = None
    cert: str | None = None
    port: int | None = None
    server: str | None = None
    status: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKMIPServer(BaseModel):
    name: str
    vdom: str = "root"
    interface: str | None = None
    interface_select_method: str | None = None
    password_configured: bool = False
    server_identity_check: str | None = None
    server_list: list[FGKMIPServerEntry] = Field(default_factory=list)
    source_ip: str | None = None
    ssl_min_proto_version: str | None = None
    username: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKerberosKeytab(BaseModel):
    name: str
    vdom: str = "root"
    keytab_configured: bool = False
    ldap_server: list[str] = Field(default_factory=list)
    pac_data: str | None = None
    principal: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterSettings(BaseModel):
    vdom: str = "root"
    hostname: str | None = None
    show_filter: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSDNProxy(BaseModel):
    name: str
    vdom: str = "root"
    password_configured: bool = False
    server: str | None = None
    server_port: int | None = None
    type: str | None = None
    username: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOnDemandSniffer(BaseModel):
    name: str
    vdom: str = "root"
    advanced_filter: str | None = None
    hosts: str | None = None
    interface: str | None = None
    max_packet_count: int | None = None
    non_ip_packet: str | None = None
    ports: list[int] = Field(default_factory=list)
    protocols: list[int] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAffinityInterrupt(BaseModel):
    id: int | None = None
    affinity_cpumask: str | None = None
    default_affinity_cpumask: str | None = None
    interrupt: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSerialPort(BaseModel):
    name: str
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFirewallRegion(BaseModel):
    id: int | None = None
    name: str | None = None
    city: list[int] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGVendorMAC(BaseModel):
    id: int | None = None
    name: str | None = None
    mac_number: int | None = None
    obsolete: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
