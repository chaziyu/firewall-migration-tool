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
    "firewall network-service-dynamic",
    "system sdn-connector",
    "system link-monitor",
    "system switch-interface",
    "system virtual-wire-pair",
    "system vdom-link",
    "system pppoe-interface",
    "vpn certificate crl",
    "vpn certificate ocsp-server",
    "vpn certificate setting",
    "system dns-server",
    "system dns64",
    "firewall dnstranslation",
    "firewall access-proxy",
    "firewall access-proxy6",
    "firewall access-proxy-virtual-host",
    "firewall access-proxy-ssh-client-cert",
    "endpoint-control fctems-override",
    "vpn ssl web realm",
    "vpn ssl web user-bookmark",
    "vpn ssl web group-bookmark",
    "vpn ipsec manualkey-interface",
    "user radius",
    "user tacacs+",
    "user peer",
    "user peergrp",
    "user fsso-polling",
    "user domain-controller",
    "user krb-keytab",
    "user certificate",
    "user external-identity-provider",
}


class FGSourceCommand(BaseModel):
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)


class FGSourceNode(BaseModel):
    node_type: str
    name: str
    commands: List[FGSourceCommand] = Field(default_factory=list)
    children: List["FGSourceNode"] = Field(default_factory=list)


class FGStructuredSourceObject(BaseModel):
    source_path: str
    name: Optional[str] = None
    source_id: Optional[str] = None
    source_context: str = "root"
    root: FGSourceNode
