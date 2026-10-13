from __future__ import annotations

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANBlockIPAction(PANNestedSourceModel):
    track_by: str | None = None
    duration: str | None = None


class PANVulnerabilityRule(PANNestedSourceModel):
    name: str | None = None
    threat_name: str | None = None
    host: str | None = None
    vendor_ids: list[str] | None = None
    severities: list[str] | None = None
    category: str | None = None
    action: str | None = None
    block_ip: PANBlockIPAction | None = None
    packet_capture: str | None = None


class PANVulnerabilityException(PANNestedSourceModel):
    name: str | None = None
    action: str | None = None
    block_ip: PANBlockIPAction | None = None
    packet_capture: str | None = None
    time_interval: str | None = None
    time_threshold: str | None = None
    time_track_by: str | None = None
    exempt_ips: list[str] | None = None


class PANVulnerabilityProfile(PANNamedSourceModel):
    rules: list[PANVulnerabilityRule] | None = None
    exceptions: list[PANVulnerabilityException] | None = None


class PANSecurityProfileGroup(PANNamedSourceModel):
    antivirus: list[str] | None = None
    anti_spyware: list[str] | None = None
    vulnerability: list[str] | None = None
    url_filtering: list[str] | None = None
    file_blocking: list[str] | None = None
    wildfire_analysis: list[str] | None = None
    data_filtering: list[str] | None = None
    gtp: list[str] | None = None
    sctp: list[str] | None = None
    ai_security: list[str] | None = None
    disable_override: str | None = None
