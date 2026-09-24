from typing import Any

from pydantic import BaseModel, Field


class FGProfileGroup(BaseModel):
    name: str
    vdom: str = "root"

    # Core security profile references
    application_list: str | None = None
    av_profile: str | None = None
    ips_sensor: str | None = None
    webfilter_profile: str | None = None
    dnsfilter_profile: str | None = None
    ssl_ssh_profile: str | None = None

    # Additional profile references
    casb_profile: str | None = None
    cifs_profile: str | None = None
    diameter_filter_profile: str | None = None
    dlp_profile: str | None = None
    emailfilter_profile: str | None = None
    file_filter_profile: str | None = None
    icap_profile: str | None = None

    # Protocol / traffic inspection helpers
    profile_protocol_options: str | None = None
    sctp_filter_profile: str | None = None
    ssh_filter_profile: str | None = None

    # Other security profiles
    ips_voip_filter: str | None = None
    videofilter_profile: str | None = None
    virtual_patch_profile: str | None = None
    voip_profile: str | None = None
    waf_profile: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)