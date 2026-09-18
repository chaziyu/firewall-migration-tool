from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

STRUCTURED_SECURITY_SECTIONS = {
    # Security/profile dependencies that are intentionally source-only until
    # their FortiOS semantics have a portable target representation.
    "application group",
    "dnsfilter domain-filter",
    "icap server",
    "icap server-group",
    "ips custom",
    "ips rule",
    "ips rule-settings",
    "diameter-filter profile",
    "sctp-filter profile",
    "ssh-filter profile",
    "videofilter profile",
    "application custom",
    "application list",
    "dlp data-type",
    "dlp dictionary",
    "dlp sensor",
    "dlp filepattern",
    "dlp profile",
    "webfilter urlfilter",
    "webfilter profile",
    "webfilter search-engine",
    "webfilter ips-urlfilter-setting",
    "webfilter ips-urlfilter-setting6",
    "webfilter ftgd-local-cat",
    "webfilter ftgd-local-rating",
    "dnsfilter profile",
    "antivirus profile",
    "antivirus settings",
    "file-filter profile",
    "emailfilter profile",
    "icap profile",
    "voip profile",
    "virtual-patch profile",
    "firewall profile-protocol-options",
    "firewall ssl-ssh-profile",
    "firewall profile-group",
    "waf profile",
    "casb profile",
    "casb saas-application",
    "casb user-activity",
    "ips settings",
}

STRUCTURED_ROUTING_SECTIONS = {
    "router rip",
    "router ripng",
    "router ospf",
    "router ospf6",
    "router bgp",
    "router isis",
    "router multicast",
    "router multicast-flow",
    "router multicast6",
}

STRUCTURED_ROUTING_DEPENDENCY_SECTIONS = {
    "router route-map",
    "router prefix-list",
    "router prefix-list6",
    "router access-list",
    "router access-list6",
    "router aspath-list",
    "router community-list",
    "router extcommunity-list",
    "router bfd",
    "router bfd6",
    "router auth-path",
    "router key-chain",
    "router setting",
}

STRUCTURED_IDENTITY_SECTIONS = {
    "firewall identity-based-route",
    "firewall auth-portal",
}

STRUCTURED_OPERATIONAL_SECTIONS = {
    "system automation-trigger",
    "system automation-action",
    "system automation-stitch",
    "system link-monitor",
    "system virtual-wire-pair",
    "system vdom-link",
    "vpn certificate crl",
    "vpn certificate ocsp-server",
    "vpn certificate setting",
    "firewall dnstranslation",
    "user radius",
    "user tacacs+",
    "user peer",
    "user peergrp",
    "user fsso-polling",
    "system fsso-polling",
    "user domain-controller",
    "user krb-keytab",
    "user certificate",
    "user external-identity-provider",
}


class FGSourceCommand(BaseModel):
    """One sanitized source operation; keys and values retain source spelling/order."""
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)
    line_number: Optional[int] = None


class FGSourceNode(BaseModel):
    """Lossless config/edit hierarchy with no FortiOS semantic interpretation."""
    node_type: str
    name: str
    commands: List[FGSourceCommand] = Field(default_factory=list)
    children: List["FGSourceNode"] = Field(default_factory=list)
    start_line_number: Optional[int] = None
    end_line_number: Optional[int] = None


class FGStructuredSourceObject(BaseModel):
    source_path: str
    name: Optional[str] = None
    source_id: Optional[str] = None
    source_context: str = "root"
    root: FGSourceNode
