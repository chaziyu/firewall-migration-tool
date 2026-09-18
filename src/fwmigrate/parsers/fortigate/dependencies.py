"""Context-aware FortiGate dependency accounting."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem
from fwmigrate.parsers.fortigate.predefined_services import (
    is_predefined_service,
    is_predefined_service_group,
)


# Values are source section families, not canonical IR types.  Keeping this
# table vendor-local prevents FortiGate-only relationships leaking into the
# generic IR while still making missing references auditable.
REFERENCE_RULES: Dict[Tuple[str, str], str] = {
    ("firewall policy", "ips-sensor"): "ips sensor",
    ("firewall policy", "internet-service-name"): "firewall internet-service-name",
    ("firewall policy", "internet-service-custom"): "firewall internet-service-custom",
    ("firewall policy", "internet-service-src-custom"): "firewall internet-service-custom",
    ("firewall policy", "internet-service6-custom"): "firewall internet-service-custom",
    ("firewall policy", "internet-service6-src-custom"): "firewall internet-service-custom",
    ("firewall policy", "profile-group"): "firewall profile-group",
    ("firewall policy", "av-profile"): "antivirus profile",
    ("firewall policy", "webfilter-profile"): "webfilter profile",
    ("firewall policy", "ssl-ssh-profile"): "firewall ssl-ssh-profile",
    ("firewall policy", "application-list"): "application list",
    ("firewall policy", "srcintf"): "system interface",
    ("firewall policy", "dstintf"): "system interface",
    ("vpn ipsec phase1-interface", "interface"): "system interface",
    ("vpn ipsec phase1-interface", "certificate"): "vpn certificate local",
    ("vpn ipsec phase2-interface", "phase1name"): "vpn ipsec phase1-interface",
    ("vpn ssl settings", "source-interface"): "system interface",
    ("vpn ssl settings", "source-address"): "firewall address",
    ("vpn ssl settings", "source-address6"): "firewall address6",
    ("vpn ssl settings", "tunnel-ip-pools"): "firewall address",
    ("vpn ssl settings", "tunnel-ipv6-pools"): "firewall address6",
    ("vpn ssl settings", "default-portal"): "vpn ssl web portal",
    ("vpn ssl web portal", "ip-pools"): "firewall address",
    ("vpn ssl web portal", "ipv6-pools"): "firewall address6",
    ("vpn ssl web portal", "split-tunneling-routing-address"): "firewall address",
    ("vpn ssl web portal", "ipv6-split-tunneling-routing-address"): "firewall address6",
    ("firewall policy", "srcaddr"): "firewall address",
    ("firewall policy", "dstaddr"): "firewall address",
    ("firewall policy", "srcaddr6"): "firewall address6",
    ("firewall policy", "dstaddr6"): "firewall address6",
    ("firewall vipgrp6", "member"): "firewall vip6",
    ("firewall policy", "service"): "firewall service custom",
    ("firewall policy", "schedule"): "firewall schedule recurring",
    ("firewall policy", "groups"): "user group",
    ("firewall policy", "users"): "user",
    ("firewall policy", "internet-service-group"): "firewall internet-service-group",
    ("firewall policy", "internet-service-src-group"): "firewall internet-service-group",
    ("firewall policy", "internet-service6-group"): "firewall internet-service-group",
    ("firewall policy", "internet-service6-src-group"): "firewall internet-service-group",
    ("firewall policy", "internet-service-custom-group"): "firewall internet-service-custom-group",
    ("firewall policy", "internet-service-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall policy", "internet-service6-custom-group"): "firewall internet-service-custom-group",
    ("firewall policy", "internet-service6-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall security-policy", "internet-service-group"): "firewall internet-service-group",
    ("firewall security-policy", "internet-service-src-group"): "firewall internet-service-group",
    ("firewall security-policy", "internet-service6-group"): "firewall internet-service-group",
    ("firewall security-policy", "internet-service6-src-group"): "firewall internet-service-group",
    ("firewall security-policy", "srcintf"): "system interface",
    ("firewall security-policy", "dstintf"): "system interface",
    ("firewall security-policy", "srcaddr"): "firewall address",
    ("firewall security-policy", "dstaddr"): "firewall address",
    ("firewall security-policy", "srcaddr6"): "firewall address6",
    ("firewall security-policy", "dstaddr6"): "firewall address6",
    ("firewall security-policy", "service"): "firewall service custom",
    ("firewall security-policy", "schedule"): "firewall schedule recurring",
    ("firewall security-policy", "groups"): "user group",
    ("firewall security-policy", "fsso-groups"): "user adgrp",
    ("firewall security-policy", "users"): "user",
    ("firewall security-policy", "app-group"): "application group",
    ("firewall security-policy", "application-list"): "application list",
    ("firewall security-policy", "av-profile"): "antivirus profile",
    ("firewall security-policy", "webfilter-profile"): "webfilter profile",
    ("firewall security-policy", "casb-profile"): "casb profile",
    ("firewall security-policy", "cifs-profile"): "cifs profile",
    ("firewall security-policy", "diameter-filter-profile"): "diameter-filter profile",
    ("firewall security-policy", "dlp-profile"): "dlp profile",
    ("firewall security-policy", "dnsfilter-profile"): "dnsfilter profile",
    ("firewall security-policy", "emailfilter-profile"): "emailfilter profile",
    ("firewall security-policy", "file-filter-profile"): "file-filter profile",
    ("firewall security-policy", "icap-profile"): "icap profile",
    ("firewall security-policy", "ips-sensor"): "ips sensor",
    ("firewall security-policy", "ips-voip-filter"): "voip profile",
    ("firewall security-policy", "profile-group"): "firewall profile-group",
    ("firewall security-policy", "profile-protocol-options"): "firewall profile-protocol-options",
    ("firewall security-policy", "sctp-filter-profile"): "sctp-filter profile",
    ("firewall security-policy", "ssh-filter-profile"): "ssh-filter profile",
    ("firewall security-policy", "ssl-ssh-profile"): "firewall ssl-ssh-profile",
    ("firewall security-policy", "videofilter-profile"): "videofilter profile",
    ("firewall security-policy", "virtual-patch-profile"): "virtual-patch profile",
    ("firewall security-policy", "voip-profile"): "voip profile",
    ("firewall security-policy", "internet-service-custom"): "firewall internet-service-custom",
    ("firewall security-policy", "internet-service-src-custom"): "firewall internet-service-custom",
    ("firewall security-policy", "internet-service-custom-group"): "firewall internet-service-custom-group",
    ("firewall security-policy", "internet-service-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall security-policy", "internet-service6-custom"): "firewall internet-service-custom",
    ("firewall security-policy", "internet-service6-src-custom"): "firewall internet-service-custom",
    ("firewall security-policy", "internet-service6-custom-group"): "firewall internet-service-custom-group",
    ("firewall security-policy", "internet-service6-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall dos-policy", "interface"): "system interface",
    ("firewall dos-policy", "srcaddr"): "firewall address",
    ("firewall dos-policy", "dstaddr"): "firewall address",
    ("firewall dos-policy", "service"): "firewall service custom",
    ("firewall dos-policy6", "interface"): "system interface",
    ("firewall dos-policy6", "srcaddr"): "firewall address6",
    ("firewall dos-policy6", "dstaddr"): "firewall address6",
    ("firewall dos-policy6", "service"): "firewall service custom",
    ("firewall policy", "identity-based-route"): "firewall identity-based-route",
    ("firewall identity-based-route rule", "device"): "system interface",
    ("firewall identity-based-route rule", "groups"): "user group",
    ("firewall auth-portal", "groups"): "user group",
    ("firewall auth-portal", "identity-based-route"): "firewall identity-based-route",
    ("router policy", "input-device"): "system interface",
    ("router policy", "output-device"): "system interface",
    ("router policy", "srcaddr"): "firewall address",
    ("router policy", "dstaddr"): "firewall address",
    ("router policy", "internet-service-custom"): "firewall internet-service-custom",
    ("router policy", "internet-service-name"): "firewall internet-service-name",
    ("router policy", "internet-service-id"): "FortiGuard Internet Service ID",
    ("router policy6", "input-device"): "system interface",
    ("router policy6", "output-device"): "system interface",
    ("router policy6", "srcaddr"): "firewall address6",
    ("router policy6", "dstaddr"): "firewall address6",
    ("router policy6", "internet-service-custom"): "firewall internet-service-custom",
    ("router policy6", "internet-service-name"): "firewall internet-service-name",
    ("router policy6", "internet-service-id"): "FortiGuard Internet Service ID",
    ("system interface", "member"): "system interface",
    ("firewall internet-service-custom-group", "member"): "firewall internet-service-custom",
    ("firewall profile-group", "ssh-filter-profile"): "ssh-filter profile",
    ("firewall profile-group", "diameter-filter-profile"): "diameter-filter profile",
    ("firewall profile-group", "sctp-filter-profile"): "sctp-filter profile",
    ("firewall profile-group", "videofilter-profile"): "videofilter profile",
    ("system link-monitor", "srcintf"): "system interface",
    ("router static", "device"): "system interface",
    ("router static6", "device"): "system interface",
    ("router static", "sdwan-zone"): "system sdwan zone",
    ("router static6", "sdwan-zone"): "system sdwan zone",
    ("router static", "dstaddr"): "firewall address",
    ("router static6", "dstaddr"): "firewall address6",
    ("firewall vip", "extintf"): "system interface",
    ("firewall vip", "srcintf-filter"): "system interface",
    ("firewall vip", "extaddr"): "firewall address",
    ("firewall vip", "mapped-addr"): "firewall address",
    ("firewall vip", "service"): "firewall service custom",
    ("firewall vip", "monitor"): "firewall ldb-monitor",
    ("firewall vip realservers", "address"): "firewall address",
    ("firewall vip realservers", "monitor"): "firewall ldb-monitor",
    ("user group", "member"): "user",
    ("vpn certificate setting", "crl"): "vpn certificate crl",
    ("vpn certificate setting", "ocsp-server"): "vpn certificate ocsp-server",
    ("system sdwan members", "interface"): "system interface",
    ("system sdwan members", "zone"): "system sdwan zone",
    ("system sdwan health-check", "members"): "system sdwan members",
    ("system sdwan service", "health-check"): "system sdwan health-check",
    ("system sdwan service", "priority-members"): "system sdwan members",
    ("system sdwan service", "priority-zone"): "system sdwan zone",
    ("system sdwan service", "src"): "firewall address",
    ("system sdwan service", "dst"): "firewall address",
    ("system sdwan service", "src6"): "firewall address6",
    ("system sdwan service", "dst6"): "firewall address6",
    ("system sdwan service", "input-device"): "system interface",
    ("system sdwan service", "input-zone"): "system zone",
    ("system sdwan service", "groups"): "user group",
    ("system sdwan service", "users"): "user",
    ("system sdwan service", "internet-service-custom"): "firewall internet-service-custom",
    ("system sdwan service", "internet-service-custom-group"): "firewall internet-service-custom-group",
    ("system sdwan service", "internet-service-name"): "firewall internet-service-name",
    ("system sdwan service", "internet-service-app-ctrl"): "FortiGuard Internet Service ID",
    ("system sdwan service", "internet-service-app-ctrl-category"): "FortiGuard Internet Service category",
    ("system sdwan service", "internet-service-app-ctrl-group"): "FortiGuard Internet Service group",
    ("system sdwan service", "internet-service-group"): "FortiGuard Internet Service group",
    ("system sdwan service sla", "edit"): "system sdwan health-check",
    ("system interface", "aggregate"): "system interface",
    ("system interface", "redundant-interface"): "system interface",
    ("system interface", "interface"): "system interface",
    ("system interface ipv6", "ip6-upstream-interface"): "system interface",
    (
        "system interface ipv6 ip6-delegated-prefix-list",
        "upstream-interface",
    ): "system interface",
}

# These are deliberately rule-specific.  ``REFERENCE_RULES`` retains the
# display/general expected type on DependencyRecord, while this map describes
# the source sections that are safe matches for a particular relationship.
# In particular, SD-WAN zones are valid policy interface selectors and VIPs
# are valid policy destinations, but neither is a global alias for an
# interface or address. Configured custom Internet Service/group references
# match only their exact indexed source sections; numeric ISDB IDs and
# database-only names use explicit external resolution modes below.
REFERENCE_TARGET_SECTIONS: Dict[Tuple[str, str], set[str]] = {
    ("vpn ipsec phase1-interface", "interface"): {"system interface"},
    ("vpn ipsec phase1-interface", "certificate"): {"vpn certificate local"},
    ("vpn ipsec phase2-interface", "phase1name"): {"vpn ipsec phase1-interface"},
    ("vpn ssl settings", "source-interface"): {"system interface"},
    ("vpn ssl settings", "source-address"): {
        "firewall address", "firewall addrgrp",
    },
    ("vpn ssl settings", "source-address6"): {
        "firewall address6", "firewall addrgrp6",
    },
    ("vpn ssl settings", "tunnel-ip-pools"): {
        "firewall address", "firewall addrgrp", "firewall ippool",
    },
    ("vpn ssl settings", "tunnel-ipv6-pools"): {
        "firewall address6", "firewall addrgrp6", "firewall ippool6",
    },
    ("vpn ssl settings", "default-portal"): {"vpn ssl web portal"},
    ("vpn ssl web portal", "ip-pools"): {
        "firewall address", "firewall addrgrp", "firewall ippool",
    },
    ("vpn ssl web portal", "ipv6-pools"): {
        "firewall address6", "firewall addrgrp6", "firewall ippool6",
    },
    ("vpn ssl web portal", "split-tunneling-routing-address"): {
        "firewall address", "firewall addrgrp",
    },
    ("vpn ssl web portal", "ipv6-split-tunneling-routing-address"): {
        "firewall address6", "firewall addrgrp6",
    },
    ("firewall vip", "extaddr"): {
        "firewall address",
    },
    ("firewall vip", "srcintf-filter"): {"system interface"},
    ("firewall vip", "mapped-addr"): {
        "firewall address",
    },
    ("firewall vip", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall vip", "monitor"): {
        "firewall ldb-monitor",
    },
    ("firewall vip realservers", "address"): {
        "firewall address",
    },
    ("firewall vip realservers", "monitor"): {
        "firewall ldb-monitor",
    },
    ("firewall policy", "srcintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall policy", "schedule"): {
        "firewall schedule recurring",
        "firewall schedule onetime",
        "firewall schedule group",
    },
    ("firewall dos-policy", "interface"): {"system interface"},
    ("firewall dos-policy", "srcaddr"): {"firewall address", "firewall addrgrp"},
    ("firewall dos-policy", "dstaddr"): {"firewall address", "firewall addrgrp"},
    ("firewall dos-policy", "service"): {"firewall service custom", "firewall service group"},
    ("firewall dos-policy6", "interface"): {"system interface"},
    ("firewall dos-policy6", "srcaddr"): {"firewall address6", "firewall addrgrp6"},
    ("firewall dos-policy6", "dstaddr"): {"firewall address6", "firewall addrgrp6"},
    ("firewall dos-policy6", "service"): {"firewall service custom", "firewall service group"},
    ("firewall policy", "dstintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall security-policy", "srcintf"): {
        "system interface", "system zone", "system sdwan zone",
    },
    ("firewall security-policy", "dstintf"): {
        "system interface", "system zone", "system sdwan zone",
    },
    ("firewall security-policy", "srcaddr"): {
        "firewall address", "firewall addrgrp",
    },
    ("firewall security-policy", "dstaddr"): {
        "firewall address", "firewall addrgrp",
    },
    ("firewall security-policy", "srcaddr6"): {
        "firewall address6", "firewall addrgrp6",
    },
    ("firewall security-policy", "dstaddr6"): {
        "firewall address6", "firewall addrgrp6",
    },
    ("firewall security-policy", "service"): {
        "firewall service custom", "firewall service group",
    },
    ("firewall security-policy", "schedule"): {
        "firewall schedule recurring", "firewall schedule onetime", "firewall schedule group",
    },
    ("firewall security-policy", "app-group"): {"application group"},
    ("firewall security-policy", "fsso-groups"): {"user adgrp"},
    ("firewall security-policy", "webfilter-profile"): {"webfilter profile"},
    ("firewall policy", "identity-based-route"): {
        "firewall identity-based-route",
    },
    ("firewall identity-based-route rule", "device"): {
        "system interface",
    },
    ("firewall identity-based-route rule", "groups"): {
        "user group",
    },
    ("firewall auth-portal", "groups"): {
        "user group",
    },
    ("firewall auth-portal", "identity-based-route"): {
        "firewall identity-based-route",
    },
    ("firewall policy", "srcaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall policy", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
        "firewall vip",
        "firewall vipgrp",
    },
    ("firewall policy", "srcaddr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall policy", "dstaddr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall vipgrp6", "member"): {"firewall vip6"},
    ("router policy", "input-device"): {
        "system interface",
    },
    ("router policy", "output-device"): {
        "system interface",
    },
    ("router policy", "srcaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router policy", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router policy6", "input-device"): {
        "system interface",
    },
    ("router policy6", "output-device"): {
        "system interface",
    },
    ("router policy6", "srcaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("router policy6", "dstaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("system interface", "member"): {
        "system interface",
    },
    ("system interface", "interface"): {"system interface"},
    ("system interface ipv6", "ip6-upstream-interface"): {"system interface"},
    (
        "system interface ipv6 ip6-delegated-prefix-list",
        "upstream-interface",
    ): {"system interface"},
    ("system interface", "aggregate"): {
        "system interface",
    },
    ("system interface", "redundant-interface"): {
        "system interface",
    },
    ("router static", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router static6", "dstaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("router static", "sdwan-zone"): {
        "system sdwan zone",
    },
    ("router static6", "sdwan-zone"): {
        "system sdwan zone",
    },
    ("router static6", "device"): {
        "system interface",
    },
    ("system sdwan members", "interface"): {
        "system interface",
        "vpn ipsec phase1-interface",
    },
    ("system sdwan members", "zone"): {
        "system sdwan zone",
    },
    ("system sdwan health-check", "members"): {
        "system sdwan members",
    },
    ("system sdwan service", "health-check"): {
        "system sdwan health-check",
    },
    ("system sdwan service", "priority-members"): {
        "system sdwan members",
    },
    ("system sdwan service", "priority-zone"): {
        "system sdwan zone",
    },
    ("system sdwan service", "src"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("system sdwan service", "dst"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("system sdwan service", "src6"): {"firewall address6", "firewall addrgrp6"},
    ("system sdwan service", "dst6"): {"firewall address6", "firewall addrgrp6"},
    ("system sdwan service", "input-device"): {"system interface", "vpn ipsec phase1-interface"},
    ("system sdwan service", "input-zone"): {"system zone"},
    ("system sdwan service", "groups"): {"user group"},
    ("system sdwan service", "users"): {"user local"},
    ("system sdwan service", "internet-service-name"): {"firewall internet-service-name"},
    ("system sdwan service sla", "edit"): {"system sdwan health-check"},
}

# P0 relationships live in this registry rather than being added by import
# time patch modules.  Targets are intentionally source-specific: a matching
# name in the wrong FortiOS object family is not a valid dependency.
REFERENCE_RULES.update({
    ("system interface", "interface"): "system interface",
    ("system zone", "interface"): "system interface",
    ("firewall address", "interface"): "system interface",
    ("firewall address", "associated-interface"): "system interface",
    ("firewall address6", "interface"): "system interface",
    ("firewall address6", "associated-interface"): "system interface",
    ("firewall addrgrp", "member"): "firewall address",
    ("firewall addrgrp", "exclude-member"): "firewall address",
    ("firewall addrgrp6", "member"): "firewall address6",
    ("firewall addrgrp6", "exclude-member"): "firewall address6",
    ("firewall service group", "member"): "firewall service custom",
    ("firewall schedule group", "member"): "firewall schedule recurring",
    ("firewall vipgrp", "member"): "firewall vip",
    ("firewall vipgrp", "interface"): "system interface",
    ("firewall vipgrp6", "member"): "firewall vip6",
    ("firewall policy", "poolname"): "firewall ippool",
    ("firewall policy", "poolname6"): "firewall ippool6",
    ("firewall policy", "pcp-poolname"): "firewall ippool",
    ("firewall ippool", "associated-interface"): "system interface",
    ("firewall ippool", "arp-intf"): "system interface",
    ("firewall ippool-grp", "member"): "firewall ippool",
    ("firewall central-snat-map", "srcintf"): "system interface",
    ("firewall central-snat-map", "dstintf"): "system interface",
    ("firewall central-snat-map", "orig-addr"): "firewall address",
    ("firewall central-snat-map", "dst-addr"): "firewall address",
    ("firewall central-snat-map", "orig-addr6"): "firewall address6",
    ("firewall central-snat-map", "dst-addr6"): "firewall address6",
    ("firewall central-snat-map", "nat-ippool"): "firewall ippool",
    ("firewall central-snat-map", "nat-ippool6"): "firewall ippool6",
    ("firewall vip6", "extintf"): "system interface",
    ("firewall vip6", "service"): "firewall service custom",
    ("firewall vip6", "srcintf-filter"): "system interface",
    ("firewall vip6 realservers", "address"): "firewall address6",
    ("firewall vip6 realservers", "monitor"): "firewall ldb-monitor",
})

PROFILE_GROUP_REFERENCE_RULES = {
    "application-list": "application list",
    "av-profile": "antivirus profile",
    "casb-profile": "casb profile",
    "cifs-profile": "cifs profile",
    "diameter-filter-profile": "diameter-filter profile",
    "dlp-profile": "dlp profile",
    "dnsfilter-profile": "dnsfilter profile",
    "emailfilter-profile": "emailfilter profile",
    "file-filter-profile": "file-filter profile",
    "icap-profile": "icap profile",
    "ips-sensor": "ips sensor",
    "ips-voip-filter": "voip profile",
    "profile-protocol-options": "firewall profile-protocol-options",
    "sctp-filter-profile": "sctp-filter profile",
    "ssh-filter-profile": "ssh-filter profile",
    "ssl-ssh-profile": "firewall ssl-ssh-profile",
    "videofilter-profile": "videofilter profile",
    "virtual-patch-profile": "virtual-patch profile",
    "voip-profile": "voip profile",
    "waf-profile": "waf profile",
    "webfilter-profile": "webfilter profile",
}

REFERENCE_RULES.update({
    ("firewall profile-group", field): target
    for field, target in PROFILE_GROUP_REFERENCE_RULES.items()
})
REFERENCE_RULES.update({
    ("firewall policy", field): target
    for field, target in PROFILE_GROUP_REFERENCE_RULES.items()
})
REFERENCE_RULES.update({
    ("firewall vip", "ssl-certificate"): "vpn certificate local",
    ("firewall ssl-ssh-profile", "caname"): "vpn certificate ca",
    ("firewall ssl-ssh-profile", "server-cert"): "vpn certificate local",
    ("user setting", "auth-cert"): "vpn certificate local",
    ("user setting", "auth-ca-cert"): "vpn certificate ca",
    ("user ldap", "ca-cert"): "vpn certificate ca",
    ("user peer", "ca"): "vpn certificate ca",
    ("user saml", "cert"): "vpn certificate local",
    ("user saml", "idp-cert"): "vpn certificate remote",
    ("system saml", "cert"): "vpn certificate local",
    ("system saml", "idp-cert"): "vpn certificate remote",
    ("vpn ipsec phase1-interface", "certificate"): "vpn certificate local",
    ("vpn ssl settings", "servercert"): "vpn certificate local",
})
REFERENCE_TARGET_SECTIONS.update({
    ("firewall profile-group", field): {target}
    for field, target in PROFILE_GROUP_REFERENCE_RULES.items()
})
REFERENCE_TARGET_SECTIONS.update({
    ("firewall policy", field): {target}
    for field, target in PROFILE_GROUP_REFERENCE_RULES.items()
})
REFERENCE_TARGET_SECTIONS.update({
    key: {value}
    for key, value in {
        ("firewall vip", "ssl-certificate"): "vpn certificate local",
        ("firewall ssl-ssh-profile", "caname"): "vpn certificate ca",
        ("firewall ssl-ssh-profile", "server-cert"): "vpn certificate local",
        ("user setting", "auth-cert"): "vpn certificate local",
        ("user setting", "auth-ca-cert"): "vpn certificate ca",
        ("user ldap", "ca-cert"): "vpn certificate ca",
        ("user peer", "ca"): "vpn certificate ca",
        ("user saml", "cert"): "vpn certificate local",
        ("user saml", "idp-cert"): "vpn certificate remote",
        ("system saml", "cert"): "vpn certificate local",
        ("system saml", "idp-cert"): "vpn certificate remote",
        ("vpn ipsec phase1-interface", "certificate"): "vpn certificate local",
        ("vpn ssl settings", "servercert"): "vpn certificate local",
    }.items()
})
# Phase 46-50 keeps the historical nested profile sections valid as targets.
for _profile_field, _nested_targets in {
    "ssh-filter-profile": {"ssh-filter profile", "firewall profile-group ssh-filter"},
    "diameter-filter-profile": {"diameter-filter profile", "firewall profile-group diameter-filter"},
    "sctp-filter-profile": {"sctp-filter profile", "firewall profile-group sctp-filter"},
    "videofilter-profile": {"videofilter profile", "firewall profile-group videofilter"},
}.items():
    REFERENCE_TARGET_SECTIONS[("firewall profile-group", _profile_field)] = _nested_targets

for _relationship, _targets in {
    ("system interface", "interface"): {"system interface"},
    ("system zone", "interface"): {"system interface"},
    ("firewall address", "interface"): {"system interface"},
    ("firewall address", "associated-interface"): {"system interface"},
    ("firewall address6", "interface"): {"system interface"},
    ("firewall address6", "associated-interface"): {"system interface"},
    ("firewall addrgrp", "member"): {"firewall address", "firewall addrgrp"},
    ("firewall addrgrp", "exclude-member"): {"firewall address"},
    ("firewall addrgrp6", "member"): {"firewall address6", "firewall addrgrp6"},
    ("firewall addrgrp6", "exclude-member"): {"firewall address6"},
    ("firewall service group", "member"): {"firewall service custom", "firewall service group"},
    ("firewall schedule group", "member"): {"firewall schedule recurring", "firewall schedule onetime"},
    ("firewall vipgrp", "member"): {"firewall vip"},
    ("firewall vipgrp", "interface"): {"system interface"},
    ("firewall vipgrp6", "member"): {"firewall vip6"},
    ("firewall policy", "poolname"): {"firewall ippool", "firewall ippool_grp"},
    ("firewall policy", "poolname6"): {"firewall ippool6"},
    ("firewall policy", "pcp-poolname"): {"firewall ippool"},
    ("firewall ippool", "associated-interface"): {"system interface"},
    ("firewall ippool", "arp-intf"): {"system interface"},
    ("firewall ippool-grp", "member"): {"firewall ippool"},
    ("firewall central-snat-map", "srcintf"): {"system interface", "system zone", "system sdwan zone"},
    ("firewall central-snat-map", "dstintf"): {"system interface", "system zone", "system sdwan zone"},
    ("firewall central-snat-map", "orig-addr"): {"firewall address", "firewall addrgrp"},
    ("firewall central-snat-map", "dst-addr"): {"firewall address", "firewall addrgrp"},
    ("firewall central-snat-map", "orig-addr6"): {"firewall address6", "firewall addrgrp6"},
    ("firewall central-snat-map", "dst-addr6"): {"firewall address6", "firewall addrgrp6"},
    ("firewall central-snat-map", "nat-ippool"): {"firewall ippool"},
    ("firewall central-snat-map", "nat-ippool6"): {"firewall ippool6"},
    ("firewall vip6", "extintf"): {"system interface"},
    ("firewall vip6", "service"): {"firewall service custom", "firewall service group"},
    ("firewall vip6", "srcintf-filter"): {"system interface"},
    ("firewall vip6 realservers", "address"): {"firewall address6", "firewall address"},
    ("firewall vip6 realservers", "monitor"): {"firewall ldb-monitor"},
}.items():
    REFERENCE_TARGET_SECTIONS.setdefault(_relationship, set()).update(_targets)

BUILTIN_REFERENCES = {
    "all", "any", "always", "none", "default", "enable", "disable",
}

SDWAN_BUILTIN_REFERENCES = {
    ("system sdwan members", "zone", "virtual-wan-link"),
    ("system sdwan service", "priority-zone", "virtual-wan-link"),
}

REFERENCE_RESOLUTION_MODES: Dict[Tuple[str, str], str] = {
    ("firewall policy", "ips-sensor"): "external",
    ("firewall policy", "internet-service-name"): "external",
    ("firewall policy", "internet-service-custom"): "external",
    ("firewall policy", "internet-service-src-custom"): "external",
    ("firewall policy", "internet-service6-custom"): "external",
    ("firewall policy", "internet-service6-src-custom"): "external",
    ("firewall policy", "internet-service-group"): "external",
    ("firewall policy", "internet-service-src-group"): "external",
    ("firewall policy", "internet-service6-group"): "external",
    ("firewall policy", "internet-service6-src-group"): "external",
    ("firewall policy", "internet-service-custom-group"): "external",
    ("firewall policy", "internet-service-src-custom-group"): "external",
    ("firewall policy", "internet-service6-custom-group"): "external",
    ("firewall policy", "internet-service6-src-custom-group"): "external",
    ("firewall security-policy", "ips-sensor"): "external",
    ("firewall security-policy", "internet-service-custom"): "external",
    ("firewall security-policy", "internet-service-src-custom"): "external",
    ("firewall security-policy", "internet-service6-custom"): "external",
    ("firewall security-policy", "internet-service6-src-custom"): "external",
    ("firewall security-policy", "internet-service-custom-group"): "external",
    ("firewall security-policy", "internet-service-src-custom-group"): "external",
    ("firewall security-policy", "internet-service6-custom-group"): "external",
    ("firewall security-policy", "internet-service6-src-custom-group"): "external",
    ("router policy", "internet-service-custom"): "external",
    ("router policy", "internet-service-name"): "external",
    ("router policy6", "internet-service-custom"): "external",
    ("router policy6", "internet-service-name"): "external",
    ("router policy", "internet-service-id"): "external",
    ("router policy6", "internet-service-id"): "external",
    ("system sdwan service", "internet-service-name"): "external",
    ("system sdwan service", "internet-service-custom"): "external",
    ("system sdwan service", "internet-service-custom-group"): "external",
    ("system sdwan service", "internet-service-app-ctrl"): "external",
    ("system sdwan service", "internet-service-app-ctrl-category"): "external",
    ("system sdwan service", "internet-service-app-ctrl-group"): "external",
    ("system sdwan service", "internet-service-group"): "external",
}

EXTERNAL_REFERENCE_NOTE = (
    "Reference requires FortiGuard/Internet Service Database or "
    "appliance-generated Internet Service data and cannot be conclusively "
    "validated from the supplied configuration."
)


def _norm(value: str) -> str:
    return " ".join(value.lower().replace("_", "-").split())


def _legacy_expected_sections(expected: str) -> set[str]:
    expected = _norm(expected)
    aliases = {
        "firewall address": {"firewall address", "firewall address6", "firewall addrgrp", "firewall addrgrp6"},
        "firewall service custom": {"firewall service custom", "firewall service group"},
        "system interface": {"system interface", "system zone"},
        "ssh-filter profile": {"ssh-filter profile", "firewall profile-group ssh-filter"},
        "diameter-filter profile": {"diameter-filter profile", "firewall profile-group diameter-filter"},
        "sctp-filter profile": {"sctp-filter profile", "firewall profile-group sctp-filter"},
        "videofilter profile": {"videofilter profile", "firewall profile-group videofilter"},
    }
    return aliases.get(expected, {expected})


def _allowed_target_sections(
    source_path: str,
    field: str,
    expected: str,
) -> set[str]:
    explicit = REFERENCE_TARGET_SECTIONS.get((_norm(source_path), _norm(field)))
    if explicit is not None:
        return {_norm(value) for value in explicit}
    return _legacy_expected_sections(expected)


def _section_matches(actual: str, expected: str) -> bool:
    """Match a legacy expected type, including the user-section prefix rule."""

    actual = _norm(actual)
    expected = _norm(expected)
    if expected == "user":
        return actual.startswith("user ")
    return actual in _legacy_expected_sections(expected)


def _allowed_section_matches(actual: str, allowed_sections: set[str]) -> bool:
    """Match explicit sections while preserving legacy ``user`` prefix matching."""

    actual = _norm(actual)
    return actual in allowed_sections or (
        "user" in allowed_sections and actual.startswith("user ")
    )


def _flatten(items: Iterable[SourceInventoryItem]) -> List[SourceInventoryItem]:
    result: List[SourceInventoryItem] = []
    for item in items:
        result.append(item)
        result.extend(_flatten(item.children))
    return result


def _reference_values(values: list[str]) -> list[str]:
    return [
        value for value in values
        if value
        and value not in {"[REDACTED]", "<redacted>"}
    ]


def _reference_resolution_mode(source_path: str, field: str) -> str:
    return REFERENCE_RESOLUTION_MODES.get(
        (_norm(source_path), _norm(field)),
        "local",
    )


def _reference_is_active(item: SourceInventoryItem, field: str) -> bool:
    """Return whether a conditional FortiGate reference has object semantics."""

    if _norm(item.source_path) != "firewall vip realservers" or field != "address":
        return True
    return any(
        _norm(command.key) == "type" and any(_norm(value) == "address" for value in command.values)
        for command in item.commands
    )


_FIELD_SPECIFIC_BUILTINS = {
    ("firewall policy", "srcintf"): {"any"},
    ("firewall policy", "dstintf"): {"any"},
    ("firewall policy", "srcaddr"): {"all"},
    ("firewall policy", "dstaddr"): {"all"},
    ("firewall policy", "srcaddr6"): {"all"},
    ("firewall policy", "dstaddr6"): {"all"},
    ("firewall policy", "service"): {"all", "none"},
    ("firewall policy", "schedule"): {"always"},
    ("firewall security-policy", "srcintf"): {"any"},
    ("firewall security-policy", "dstintf"): {"any"},
    ("firewall security-policy", "srcaddr"): {"all"},
    ("firewall security-policy", "dstaddr"): {"all"},
    ("firewall security-policy", "srcaddr6"): {"all"},
    ("firewall security-policy", "dstaddr6"): {"all"},
    ("firewall security-policy", "service"): {"all", "none"},
    ("firewall security-policy", "schedule"): {"always"},
    ("firewall dos-policy", "interface"): {"any"},
    ("firewall dos-policy", "srcaddr"): {"all"},
    ("firewall dos-policy", "dstaddr"): {"all"},
    ("firewall dos-policy", "service"): {"all", "none"},
    ("firewall dos-policy6", "interface"): {"any"},
    ("firewall dos-policy6", "srcaddr"): {"all"},
    ("firewall dos-policy6", "dstaddr"): {"all"},
    ("firewall dos-policy6", "service"): {"all", "none"},
    ("router policy", "srcaddr"): {"all"},
    ("router policy", "dstaddr"): {"all"},
    ("router policy6", "srcaddr"): {"all"},
    ("router policy6", "dstaddr"): {"all"},
    ("firewall vip", "extintf"): {"any"},
    ("firewall vip", "service"): {"all", "none"},
    ("firewall vip6", "extintf"): {"any"},
    ("firewall vip6", "service"): {"all", "none"},
    ("vpn ssl settings", "source-interface"): {"any"},
    ("vpn ssl settings", "source-address"): {"all"},
    ("vpn ssl settings", "source-address6"): {"all"},
}


def _is_field_specific_builtin(source_path: str, field: str, reference: str) -> bool:
    values = _FIELD_SPECIFIC_BUILTINS.get((_norm(source_path), _norm(field)), set())
    return _norm(reference) in values


def _is_predefined_service_group_reference(
    source_path: str,
    field: str,
    reference: str,
) -> bool:
    if not is_predefined_service_group(reference):
        return False
    if _norm(source_path) == "firewall service group" and field == "member":
        return True
    return field == "service" and _norm(source_path) in {
        "firewall policy",
        "firewall security-policy",
        "firewall dos-policy",
        "firewall dos-policy6",
    }


def _candidate_index(
    items: Iterable[SourceInventoryItem],
) -> Dict[Tuple[str, str], List[SourceInventoryItem]]:
    index: Dict[Tuple[str, str], List[SourceInventoryItem]] = {}
    for item in items:
        context = item.source_context or "root"
        names = dict.fromkeys(
            str(name)
            for name in (item.name, item.source_id)
            if name is not None and str(name)
        )
        for name in names:
            candidates = index.setdefault((context, name), [])
            if not any(
                candidate.source_path == item.source_path
                and candidate.name == item.name
                and candidate.source_id == item.source_id
                for candidate in candidates
            ):
                candidates.append(item)
    return index


def _matching_candidates(
    index: Dict[Tuple[str, str], List[SourceInventoryItem]],
    *,
    source_context: str,
    reference: str,
    allowed_sections: set[str],
) -> List[SourceInventoryItem]:
    return [
        candidate
        for candidate in index.get((source_context, reference), [])
        if _allowed_section_matches(candidate.source_path, allowed_sections)
    ]


def _matching_service_candidates(
    index: Dict[Tuple[str, str], List[SourceInventoryItem]],
    *,
    source_context: str,
    reference: str,
    allowed_sections: set[str],
) -> List[SourceInventoryItem]:
    for section in ("firewall service custom", "firewall service group"):
        if section not in allowed_sections:
            continue
        candidates = [
            candidate
            for candidate in index.get((source_context, reference), [])
            if _norm(candidate.source_path) == section
        ]
        if candidates:
            return candidates
    return []


def _ambiguous_candidates(
    candidates: List[SourceInventoryItem],
) -> List[SourceInventoryItem]:
    by_section: Dict[str, List[SourceInventoryItem]] = {}
    for candidate in candidates:
        by_section.setdefault(_norm(candidate.source_path), []).append(candidate)
    return [
        candidate
        for same_section in by_section.values()
        if len(same_section) > 1
        for candidate in same_section
    ]


def _ambiguity_note(candidates: List[SourceInventoryItem]) -> str:
    sections = sorted({_norm(candidate.source_path) for candidate in candidates})
    return (
        "Reference is ambiguous in the same VDOM/context; "
        f"{len(candidates)} valid targets match: {', '.join(sections)}."
    )


def _pool_reference_collision(candidates: List[SourceInventoryItem]) -> bool:
    return {
        _norm(candidate.source_path) for candidate in candidates
    } >= {"firewall ippool", "firewall ippool-grp"}


def build_dependency_registry(items: Iterable[SourceInventoryItem]) -> List[DependencyRecord]:
    """Build deterministic context-scoped dependency records."""

    all_items = _flatten(items)
    index = _candidate_index(all_items)

    dependencies: List[DependencyRecord] = []
    for item in all_items:
        source_context = item.source_context or "root"
        source_path = _norm(item.source_path)
        if source_path == "system sdwan service sla" and item.name:
            health_check = _matching_candidates(
                index,
                source_context=source_context,
                reference=item.name,
                allowed_sections={"system sdwan health-check"},
            )
            resolved = len(health_check) == 1
            dependencies.append(DependencyRecord(
                source_context=source_context,
                source_path=source_path,
                source_object=item.name,
                source_field="edit",
                reference=item.name,
                expected_type="system sdwan health-check",
                result="RESOLVED" if resolved else "UNRESOLVED",
                target_path="system sdwan health-check" if resolved else None,
                notes="Nested SD-WAN service SLA references its health-check by edit name.",
            ))
        for command in item.commands:
            if getattr(command, "operation", "set") not in {"set", "append"}:
                continue
            field = _norm(command.key)
            expected = REFERENCE_RULES.get((source_path, field))
            if expected is None or not _reference_is_active(item, field):
                continue
            resolution_mode = _reference_resolution_mode(source_path, field)
            allowed_sections = _allowed_target_sections(
                source_path,
                field,
                expected,
            )
            for reference in _reference_values(command.values):
                candidates = (
                    _matching_service_candidates(
                        index,
                        source_context=source_context,
                        reference=reference,
                        allowed_sections=allowed_sections,
                    )
                    if expected == "firewall service custom"
                    else _matching_candidates(
                        index,
                        source_context=source_context,
                        reference=reference,
                        allowed_sections=allowed_sections,
                    )
                )
                ambiguous = _ambiguous_candidates(candidates)
                pool_collision = (
                    source_path == "firewall policy"
                    and field == "poolname"
                    and _pool_reference_collision(candidates)
                )
                self_reference = (
                    source_path == "system interface"
                    and field == "member"
                    and item.name == reference
                )
                target = None
                predefined_service = False
                predefined_service_group = False
                reason = None
                if self_reference:
                    result = "UNRESOLVED"
                    note = "Interface member cannot reference its own interface."
                    reason = "self-reference"
                elif ambiguous or pool_collision:
                    result = "UNRESOLVED"
                    note = (
                        "Reference is ambiguous in the same VDOM/context; both "
                        "firewall ippool and firewall ippool_grp match this policy poolname."
                        if pool_collision
                        else _ambiguity_note(ambiguous)
                    )
                    reason = "ambiguous-reference"
                elif candidates:
                    target = candidates[0]
                    result = "RESOLVED"
                    note = None
                elif _is_field_specific_builtin(source_path, field, reference):
                    # A documented FortiOS selector is not an object reference.
                    continue
                elif (source_path, field, _norm(reference)) in SDWAN_BUILTIN_REFERENCES:
                    result = "RESOLVED"
                    note = "FortiOS built-in virtual-wan-link zone."
                    target = None
                elif _is_predefined_service_group_reference(
                    source_path, field, reference
                ):
                    predefined_service_group = True
                    result = "RESOLVED"
                    note = (
                        "FortiOS predefined service group name resolved; "
                        "target semantic expansion is not modeled."
                    )
                    target = None
                elif expected == "firewall service custom" and is_predefined_service(reference):
                    predefined_service = True
                    result = "RESOLVED"
                    note = (
                        "FortiOS 7.4.x predefined service name resolved; "
                        "target semantic expansion is not modeled."
                    )
                else:
                    result = (
                        "EXTERNAL"
                        if resolution_mode in {"external", "local-or-external"}
                        else "UNRESOLVED"
                    )
                    note = (
                        EXTERNAL_REFERENCE_NOTE
                        if result == "EXTERNAL"
                        else "Reference was not found in the same VDOM/context."
                    )
                dependencies.append(DependencyRecord(
                    source_context=source_context,
                    source_path=source_path,
                    source_object=item.name or item.source_id,
                    source_field=command.key,
                    reference=reference,
                    expected_type=expected,
                    result=result,
                    target_path=(
                        _norm(target.source_path) if target
                        else "fortigate predefined service" if predefined_service
                        else "fortigate predefined service group" if predefined_service_group
                        else None
                    ),
                    notes=note,
                    reason=reason,
                ))
                if target is not None and (
                    source_path == "firewall policy"
                    and field == "dstaddr6"
                    and _norm(target.source_path) in {"firewall vip6", "firewall vipgrp6"}
                ):
                    dependencies.append(DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field="dstaddr6-vip",
                        reference=reference,
                        expected_type="firewall vip6",
                        result="RESOLVED",
                        target_path=_norm(target.source_path),
                        notes="Separate IPv6 DNAT/VIP relationship.",
                    ))
    profile_fields = {_norm(field) for field in PROFILE_GROUP_REFERENCE_RULES}
    effective_profile_values: Dict[Tuple[str, str, str], List[str]] = {}
    has_profile_group = False
    for item in all_items:
        if _norm(item.source_path) != "firewall profile-group":
            continue
        has_profile_group = True
        context = item.source_context or "root"
        source_object = item.name or item.source_id
        for command in item.commands:
            field = _norm(command.key)
            if field not in profile_fields:
                continue
            key = (context, source_object, field)
            values = _reference_values(command.values)
            operation = str(getattr(command, "operation", "set")).lower()
            if operation == "set":
                effective_profile_values[key] = list(values)
            elif operation == "append":
                effective_profile_values.setdefault(key, []).extend(values)
            elif operation == "unset":
                effective_profile_values.pop(key, None)

    if has_profile_group:
        filtered: List[DependencyRecord] = []
        seen_profile_dependencies: set[Tuple[str, str, str, str]] = set()
        for dependency in dependencies:
            source_path = _norm(dependency.source_path)
            field = _norm(dependency.source_field)
            if source_path != "firewall profile-group" or field not in profile_fields:
                filtered.append(dependency)
                continue
            key = (
                dependency.source_context or "root",
                dependency.source_object or "",
                field,
            )
            if dependency.reference not in effective_profile_values.get(key, []):
                continue
            dependency_key = (*key, dependency.reference)
            if dependency_key in seen_profile_dependencies:
                continue
            seen_profile_dependencies.add(dependency_key)
            filtered.append(dependency)
        dependencies = filtered

    return dependencies
