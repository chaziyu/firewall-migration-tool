from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.source_tree import FGSourceNode

STRUCTURED_SECURITY_SECTIONS = {
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
}

STRUCTURED_OPERATIONAL_SECTIONS = {
    "system automation-trigger",
    "system automation-action",
    "system automation-stitch",
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
    root: FGSourceNode
