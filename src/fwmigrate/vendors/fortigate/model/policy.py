from typing import Any

from pydantic import BaseModel, Field


class FGPolicy(BaseModel):
    # Identity / context
    policy_id: int | None = None
    vdom: str = "root"
    name: str | None = None

    # Interfaces
    srcintf: list[str] | None = None
    dstintf: list[str] | None = None

    # Addresses
    srcaddr: list[str] | None = None
    dstaddr: list[str] | None = None

    srcaddr6: list[str] | None = None
    dstaddr6: list[str] | None = None

    srcaddr_negate: str | None = None
    dstaddr_negate: str | None = None
    srcaddr6_negate: str | None = None
    dstaddr6_negate: str | None = None

    # Services / schedule
    service: list[str] | None = None
    service_negate: str | None = None
    schedule: str | None = None

    # Identity / authentication
    groups: list[str] | None = None
    users: list[str] | None = None

    # Action
    action: str | None = None

    # Policy-based IPsec
    vpntunnel: str | None = None

    # NAT
    nat: str | None = None
    nat64: str | None = None
    nat46: str | None = None
    natinbound: str | None = None
    natoutbound: str | None = None
    natip: str | None = None
    ippool: str | None = None
    poolname: list[str] | None = None
    poolname6: list[str] | None = None

    # Internet Service matching
    internet_service: str | None = None

    internet_service_name: list[str] | None = None
    internet_service_group: list[str] | None = None
    internet_service_custom: list[str] | None = None

    internet_service_src: str | None = None

    internet_service_src_name: list[str] | None = None
    internet_service_src_group: list[str] | None = None
    internet_service_src_custom: list[str] | None = None

    # Security inspection
    utm_status: str | None = None
    inspection_mode: str | None = None

    profile_type: str | None = None
    profile_group: str | None = None
    profile_protocol_options: str | None = None
    per_ip_shaper: str | None = None

    av_profile: str | None = None
    ips_sensor: str | None = None
    application_list: str | None = None
    webfilter_profile: str | None = None
    dnsfilter_profile: str | None = None
    ssl_ssh_profile: str | None = None

    # State / metadata
    status: str | None = None
    logtraffic: str | None = None
    comments: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
