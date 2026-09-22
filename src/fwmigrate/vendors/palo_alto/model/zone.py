from __future__ import annotations

from .common import PANNamedSourceModel


class PANZone(PANNamedSourceModel):
    network_type: str | None = None
    members: list[str] | None = None
    zone_protection_profile: str | None = None
    packet_buffer_protection: str | None = None
    network_inspection: str | None = None
    pre_nat_user_identification: str | None = None
    pre_nat_device_identification: str | None = None
    pre_nat_source_policy_lookup: str | None = None
    pre_nat_source_ip_downstream: str | None = None
    log_setting: str | None = None
    user_identification: str | None = None
    device_identification: str | None = None
    user_acl_include: list[str] | None = None
    user_acl_exclude: list[str] | None = None
    device_acl_include: list[str] | None = None
    device_acl_exclude: list[str] | None = None
