"""Declarative FortiGate source field metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Iterable, Mapping


@dataclass(frozen=True, slots=True)
class SectionSpec:
    """
    Primitive source-field shape for one FortiGate config section.

    Field names use their original FortiGate CLI spelling.

    This registry describes only how explicit source values should be
    represented before FortiGate semantic extraction.

    It does not:
        - normalize field names
        - construct models
        - classify secrets
        - apply FortiOS defaults
        - resolve references
        - perform validation
        - know export/report destinations
    """

    source_path: str

    list_fields: frozenset[str] = field(
        default_factory=frozenset
    )

    integer_fields: frozenset[str] = field(
        default_factory=frozenset
    )

    integer_list_fields: frozenset[str] = field(
        default_factory=frozenset
    )

    scalar_fields: frozenset[str] = field(
        default_factory=frozenset
    )


_SECTION_REGISTRY: dict[str, SectionSpec] = {}
SECTION_REGISTRY: Mapping[str, SectionSpec] = MappingProxyType(
    _SECTION_REGISTRY
)


def _fields(*names: str) -> frozenset[str]:
    return frozenset(names)


def register_section(spec: SectionSpec) -> None:
    """Register one immutable section specification."""

    if spec.source_path in _SECTION_REGISTRY:
        raise ValueError(
            f"Section already registered: {spec.source_path!r}"
        )

    categories = {
        "list_fields": spec.list_fields,
        "integer_fields": spec.integer_fields,
        "integer_list_fields": spec.integer_list_fields,
        "scalar_fields": spec.scalar_fields,
    }

    names = list(categories)

    for index, left_name in enumerate(names):
        for right_name in names[index + 1:]:
            overlap = (
                categories[left_name]
                & categories[right_name]
            )

            if overlap:
                raise ValueError(
                    f"{spec.source_path!r}: "
                    f"fields {sorted(overlap)!r} appear in both "
                    f"{left_name} and {right_name}"
                )

    _SECTION_REGISTRY[spec.source_path] = spec


def get_section_spec(
    source_path: str,
) -> SectionSpec | None:
    return SECTION_REGISTRY.get(source_path)


def is_registered_section(
    source_path: str,
) -> bool:
    return source_path in SECTION_REGISTRY


def registered_sections() -> tuple[str, ...]:
    return tuple(sorted(SECTION_REGISTRY))


# ----------------------------------------------------------------------
# Interfaces / zones
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system interface",
        list_fields=_fields(
            "allowaccess",
            "member",
            "fail-alert-interfaces",
            "fail-detect-option",
            "dns-server-protocol",
            "security-groups",
        ),
        integer_fields=_fields(
            "vlanid",
            "vrf",
            "mtu",
            "tcp-mss",
            "distance",
            "priority",
            "ha-priority",
            "min-links",
            "weight",
            "snmp-index",
            "link-up-delay",
            "link-down-delay",
            "dhcp-renew-time",
        ),
        scalar_fields=_fields(
            "type",
            "mode",
            "ip",
            "interface",
            "alias",
            "description",
            "status",
            "role",
            "defaultgw",
            "lacp-mode",
            "lacp-speed",
            "aggregate-type",
            "management-ip",
            "dhcp-relay-ip",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system interface secondaryip",
        list_fields=_fields(
            "allowaccess",
        ),
        integer_fields=_fields(
            "ha-priority",
        ),
        scalar_fields=_fields(
            "ip",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system zone",
        list_fields=_fields(
            "interface",
        ),
        scalar_fields=_fields(
            "description",
            "intrazone",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system zone tagging",
        list_fields=_fields(
            "tags",
        ),
        scalar_fields=_fields(
            "category",
        ),
    )
)


# ----------------------------------------------------------------------
# Addresses
# ----------------------------------------------------------------------

ADDRESS_SCALAR_FIELDS = _fields(
    "type",
    "subnet",
    "start-ip",
    "end-ip",
    "fqdn",
    "wildcard",
    "wildcard-fqdn",
    "associated-interface",
    "allow-routing",
    "comment",
)

register_section(
    SectionSpec(
        source_path="firewall address",
        integer_fields=_fields(
            "cache-ttl",
            "route-tag",
            "color",
        ),
        scalar_fields=ADDRESS_SCALAR_FIELDS,
    )
)

register_section(
    SectionSpec(
        source_path="firewall address6",
        integer_fields=_fields(
            "cache-ttl",
            "route-tag",
            "color",
        ),
        scalar_fields=_fields(
            "type",
            "ip6",
            "start-ip",
            "end-ip",
            "fqdn",
            "associated-interface",
            "allow-routing",
            "comment",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall address tagging",
        list_fields=_fields(
            "tags",
        ),
        scalar_fields=_fields(
            "category",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall addrgrp",
        list_fields=_fields(
            "member",
            "exclude-member",
        ),
        integer_fields=_fields(
            "color",
        ),
        scalar_fields=_fields(
            "exclude",
            "comment",
            "type",
            "category",
            "allow-routing",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall addrgrp6",
        list_fields=_fields(
            "member",
            "exclude-member",
        ),
        integer_fields=_fields(
            "color",
        ),
        scalar_fields=_fields(
            "exclude",
            "comment",
            "type",
            "category",
            "allow-routing",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall addrgrp tagging",
        list_fields=_fields(
            "tags",
        ),
        scalar_fields=_fields(
            "category",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall wildcard-fqdn custom",
        scalar_fields=_fields(
            "wildcard-fqdn",
            "comment",
        ),
    )
)


# ----------------------------------------------------------------------
# Services
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall service category",
        scalar_fields=_fields(
            "comment",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall service custom",
        integer_fields=_fields(
            "protocol-number",
            "icmptype",
            "icmpcode",
        ),
        scalar_fields=_fields(
            "category",
            "protocol",
            "tcp-portrange",
            "udp-portrange",
            "sctp-portrange",
            "proxy",
            "comment",
            "session-ttl",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall service group",
        list_fields=_fields(
            "member",
        ),
        scalar_fields=_fields(
            "proxy",
            "comment",
        ),
    )
)

# ----------------------------------------------------------------------
# Schedules
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall schedule group",
        list_fields=_fields("member"),
        integer_fields=_fields("color"),
        scalar_fields=_fields("fabric-object"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall schedule onetime",
        integer_fields=_fields("color", "expiration-days"),
        scalar_fields=_fields("start", "end", "start-utc", "end-utc", "fabric-object"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall schedule recurring",
        list_fields=_fields("day"),
        integer_fields=_fields("color"),
        scalar_fields=_fields("start", "end", "fabric-object"),
    )
)

# ----------------------------------------------------------------------
# Firewall policy
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall policy",

        list_fields=_fields(
            "srcintf",
            "dstintf",
            "srcaddr",
            "dstaddr",
            "srcaddr6",
            "dstaddr6",
            "service",
            "groups",
            "users",
            "poolname",
            "poolname6",

            "internet-service-name",
            "internet-service-group",
            "internet-service-custom",
            "internet-service-custom-group",

            "internet-service-src-name",
            "internet-service-src-group",
            "internet-service-src-custom",
            "internet-service-src-custom-group",

            "internet-service6-name",
            "internet-service6-group",
            "internet-service6-custom",
            "internet-service6-custom-group",

            "internet-service6-src-name",
            "internet-service6-src-group",
            "internet-service6-src-custom",
            "internet-service6-src-custom-group",
        ),

        scalar_fields=_fields(
            "name",
            "status",
            "action",
            "schedule",
            "nat",
            "ippool",

            "session-ttl",

            "srcaddr-negate",
            "dstaddr-negate",
            "srcaddr6-negate",
            "dstaddr6-negate",
            "service-negate",

            "internet-service",
            "internet-service-src",

            "utm-status",
            "inspection-mode",
            "profile-type",
            "profile-group",

            "av-profile",
            "ips-sensor",
            "application-list",
            "webfilter-profile",
            "dnsfilter-profile",
            "ssl-ssh-profile",

            "logtraffic",
            "comments",

            "vpntunnel",
        ),
    )
)


# ----------------------------------------------------------------------
# NAT / VIP
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall ippool",
        list_fields=_fields(
            "exclude-ip",
        ),
        integer_fields=_fields(
            "startport",
            "endport",
            "block-size",
            "port-per-user",
        ),
        scalar_fields=_fields(
            "type",
            "startip",
            "endip",
            "source-startip",
            "source-endip",
            "associated-interface",
            "arp-reply",
            "arp-intf",
            "permit-any-host",
            "nat64",
            "add-nat64-route",
            "comments",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall vip",
        list_fields=_fields(
            "extaddr",
            "mappedip",
            "monitor",
            "service",
        ),
        scalar_fields=_fields(
            "uuid",
            "status",
            "type",
            "extip",
            "extintf",
            "mapped-addr",
            "portforward",
            "protocol",
            "extport",
            "mappedport",
            "arp-reply",
            "nat-source-vip",
            "ldb-method",
            "server-type",
            "comment",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall vip realservers",
        list_fields=_fields(
            "monitor",
        ),
        integer_fields=_fields(
            "port",
            "weight",
        ),
        scalar_fields=_fields(
            "ip",
            "address",
            "status",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall vipgrp",
        list_fields=_fields(
            "member",
        ),
        scalar_fields=_fields(
            "uuid",
            "interface",
            "comments",
        ),
    )
)


# ----------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="router static",
        list_fields=_fields(
            "sdwan-zone",
        ),
        integer_fields=_fields(
            "distance",
            "priority",
            "vrf",
            "tag",
        ),
        scalar_fields=_fields(
            "dst",
            "dstaddr",
            "device",
            "gateway",
            "dynamic-gateway",
            "src",
            "preferred-source",
            "status",
            "blackhole",
            "comment",
        ),
    )
)


# ----------------------------------------------------------------------
# IPsec
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="vpn ipsec phase1-interface",
        list_fields=_fields(
            "proposal",
            "certificate",
        ),
        integer_fields=_fields(
            "keylife",
            "dpd-retrycount",
            "distance",
            "priority",
        ),
        integer_list_fields=_fields(
            "dhgrp",
        ),
        scalar_fields=_fields(
            "type",
            "interface",
            "local-gw",
            "remote-gw",
            "remotegw-ddns",
            "ike-version",
            "authmethod",
            "authmethod-remote",
            "mode",
            "nattraversal",
            "dpd",
            "dpd-retryinterval",
            "localid",
            "localid-type",
            "peerid",
            "comments",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ipsec phase2-interface",
        list_fields=_fields(
            "proposal",
        ),
        integer_fields=_fields(
            "keylifeseconds",
            "keylifekbs",
            "protocol",
            "src-port",
            "dst-port",
        ),
        integer_list_fields=_fields(
            "dhgrp",
        ),
        scalar_fields=_fields(
            "phase1name",
            "pfs",
            "src-addr-type",
            "src-subnet",
            "src-start-ip",
            "src-end-ip",
            "src-name",
            "dst-addr-type",
            "dst-subnet",
            "dst-start-ip",
            "dst-end-ip",
            "dst-name",
            "replay",
            "auto-negotiate",
            "comments",
        ),
    )
)


# ----------------------------------------------------------------------
# DHCP
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system dhcp server",
        integer_fields=_fields(
            "lease-time",
        ),
        scalar_fields=_fields(
            "status",
            "interface",
            "server-type",
            "ip-mode",
            "default-gateway",
            "netmask",
            "dns-service",
            "dns-server1",
            "dns-server2",
            "dns-server3",
            "dns-server4",
            "timezone-option",
            "timezone",
            "relay-agent",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system dhcp server ip-range",
        integer_fields=_fields(
            "lease-time",
        ),
        scalar_fields=_fields(
            "start-ip",
            "end-ip",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system dhcp server exclude-range",
        integer_fields=_fields(
            "lease-time",
        ),
        scalar_fields=_fields(
            "start-ip",
            "end-ip",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system dhcp server reserved-address",
        scalar_fields=_fields(
            "ip",
            "mac",
            "description",
            "action",
            "type",
        ),
    )
)


# ----------------------------------------------------------------------
# SD-WAN
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system sdwan",
        scalar_fields=_fields(
            "status",
            "load-balance-mode",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system sdwan zone",
        integer_fields=_fields(
            "minimum-sla-meet-members",
        ),
        scalar_fields=_fields(
            "advpn-health-check",
            "advpn-select",
            "service-sla-tie-break",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system sdwan members",
        integer_fields=_fields(
            "priority",
            "cost",
            "weight",
        ),
        scalar_fields=_fields(
            "interface",
            "zone",
            "gateway",
            "source",
            "status",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system sdwan health-check",
        integer_list_fields=_fields(
            "members",
        ),
        integer_fields=_fields(
            "interval",
            "failtime",
            "recoverytime",
        ),
        scalar_fields=_fields(
            "protocol",
            "server",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system sdwan service",
        list_fields=_fields(
            "src",
            "dst",
            "priority-zone",
            "health-check",
        ),
        integer_list_fields=_fields(
            "priority-members",
        ),
        scalar_fields=_fields(
            "name",
            "mode",
            "status",
        ),
    )
)


# ----------------------------------------------------------------------
# SSL VPN
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="vpn ssl settings",
        list_fields=_fields(
            "source-interface",
            "source-address",
            "source-address6",
            "tunnel-ip-pools",
            "tunnel-ipv6-pools",
        ),
        integer_fields=_fields(
            "auth-timeout",
            "idle-timeout",
            "port",
        ),
        scalar_fields=_fields(
            "status",
            "ssl-min-proto-ver",
            "ssl-max-proto-ver",
            "dns-server1",
            "dns-server2",
            "servercert",
            "default-portal",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ssl web portal",
        list_fields=_fields(
            "ip-pools",
            "ipv6-pools",
            "split-tunneling-routing-address",
            "ipv6-split-tunneling-routing-address",
            "host-check-policy",
        ),
        scalar_fields=_fields(
            "tunnel-mode",
            "ipv6-tunnel-mode",
            "split-tunneling",
            "ipv6-split-tunneling",
            "limit-user-logins",
            "forticlient-download",
            "web-mode",
            "host-check",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ssl web host-check-software",
        scalar_fields=_fields(
            "guid",
            "type",
            "os-type",
            "version",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ssl web host-check-software check-item-list",
        list_fields=_fields(
            "md5s",
        ),
        scalar_fields=_fields(
            "action",
            "type",
            "target",
            "version",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ssl settings authentication-rule",
        list_fields=_fields(
            "groups",
            "users",
            "source-address",
            "source-address6",
            "source-interface",
        ),
        scalar_fields=_fields(
            "auth",
            "cipher",
            "client-cert",
            "portal",
            "realm",
            "source-address-negate",
            "source-address6-negate",
            "user-peer",
        ),
    )
)


# ----------------------------------------------------------------------
# Users
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="user local",
        integer_fields=_fields(
            "id",
            "auth-concurrent-value",
            "authtimeout",
        ),
        scalar_fields=_fields(
            "auth-concurrent-override",
            "email-to",
            "fortitoken",
            "ldap-server",
            "passwd-policy",
            "passwd-time",
            "ppk-identity",
            "qkd-profile",
            "radius-server",
            "sms-custom-server",
            "sms-phone",
            "sms-server",
            "status",
            "tacacs+-server",
            "two-factor",
            "two-factor-authentication",
            "two-factor-notification",
            "type",
            "username-sensitivity",
            "workstation",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user group",
        list_fields=_fields(
            "member",
        ),
        integer_fields=_fields(
            "id",
            "authtimeout",
            "auth-concurrent-value",
        ),
        scalar_fields=_fields(
            "group-type",
            "auth-concurrent-override",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user group match",
        scalar_fields=_fields(
            "server-name",
            "group-name",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user group guest",
        scalar_fields=_fields(
            "comment",
            "email",
            "expiration",
            "mobile-phone",
            "name",
            "sponsor",
            "user-id",
        ),
    )
)


# ----------------------------------------------------------------------
# Administrators
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system admin",
        list_fields=_fields(
            "vdom",
            "guest-usergroups",
        ),
        scalar_fields=_fields(
            "accprofile",
            "accprofile-override",
            "comments",
            "email-to",
            "fortitoken",
            "guest-auth",
            "peer-auth",
            "peer-group",
            "remote-auth",
            "remote-group",
            "schedule",
            "sms-custom-server",
            "sms-phone",
            "sms-server",
            "ssh-certificate",
            "two-factor",
            "two-factor-authentication",
            "two-factor-notification",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile",
        integer_fields=_fields(
            "admintimeout",
        ),
        scalar_fields=_fields(
            "admintimeout-override",
            "authgrp",
            "cli-config",
            "cli-diagnose",
            "cli-exec",
            "cli-get",
            "cli-show",
            "comments",
            "ftviewgrp",
            "fwgrp",
            "loggrp",
            "netgrp",
            "scope",
            "secfabgrp",
            "sysgrp",
            "system-execute-ssh",
            "system-execute-telnet",
            "utmgrp",
            "vpngrp",
            "wanoptgrp",
            "wifi",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile fwgrp-permission",
        scalar_fields=_fields(
            "address",
            "others",
            "policy",
            "schedule",
            "service",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile loggrp-permission",
        scalar_fields=_fields(
            "config",
            "data-access",
            "report-access",
            "threat-weight",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile netgrp-permission",
        scalar_fields=_fields(
            "cfg",
            "packet-capture",
            "route-cfg",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile sysgrp-permission",
        scalar_fields=_fields(
            "admin",
            "cfg",
            "mnt",
            "upd",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system accprofile utmgrp-permission",
        scalar_fields=_fields(
            "antivirus",
            "application-control",
            "casb",
            "dlp",
            "dnsfilter",
            "emailfilter",
            "endpoint-control",
            "file-filter",
            "icap",
            "ips",
            "videofilter",
            "virtual-patch",
            "voip",
            "waf",
            "webfilter",
        ),
    )
)


# ----------------------------------------------------------------------
# IPS
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="ips sensor",
        scalar_fields=_fields(
            "comment",
            "block-malicious-url",
            "scan-botnet-connections",
            "extended-log",
            "replacemsg-group",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="ips sensor entries",
        list_fields=_fields(
            "cve",
        ),
        integer_fields=_fields(
            "rate-count",
            "rate-duration",
        ),
        integer_list_fields=_fields(
            "rule",
            "vuln-type",
        ),
        scalar_fields=_fields(
            "application",
            "os",
            "protocol",
            "severity",
            "location",
            "action",
            "default-action",
            "default-status",
            "status",
            "log",
            "log-packet",
            "log-attack-context",
            "quarantine",
            "quarantine-expiry",
            "quarantine-log",
            "rate-mode",
            "rate-track",
            "last-modified",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="ips sensor entries exempt-ip",
        scalar_fields=_fields(
            "src-ip",
            "dst-ip",
        ),
    )
)


# ----------------------------------------------------------------------
# Security profile groups
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall profile-group",
        scalar_fields=_fields(
            "application-list",
            "av-profile",
            "casb-profile",
            "cifs-profile",
            "diameter-filter-profile",
            "dlp-profile",
            "dnsfilter-profile",
            "emailfilter-profile",
            "file-filter-profile",
            "icap-profile",
            "ips-sensor",
            "ips-voip-filter",
            "profile-protocol-options",
            "sctp-filter-profile",
            "ssh-filter-profile",
            "ssl-ssh-profile",
            "videofilter-profile",
            "virtual-patch-profile",
            "voip-profile",
            "waf-profile",
            "webfilter-profile",
        ),
    )
)


# ----------------------------------------------------------------------
# Diagnostics
# ----------------------------------------------------------------------

def get_section_capability(
    source_path: str,
    encountered_fields: Iterable[str] = (),
) -> dict[str, object]:
    """
    Describe which raw source fields are currently declared.

    Intended for diagnostics and tests rather than normal extraction.
    """

    spec = get_section_spec(source_path)
    encountered = set(encountered_fields)

    if spec is None:
        return {
            "source_path": source_path,
            "registered": False,
            "known_fields": [],
            "unknown_fields": sorted(encountered),
        }

    known = (
        spec.list_fields
        | spec.integer_fields
        | spec.integer_list_fields
        | spec.scalar_fields
    )

    return {
        "source_path": source_path,
        "registered": True,
        "known_fields": sorted(known),
        "unknown_fields": sorted(
            encountered - known
        ),
    }



# ----------------------------------------------------------------------
# System External resource
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system external-resource",
        integer_fields=_fields(
            "refresh-rate",
        ),
        scalar_fields=_fields(
            "resource",
            "type",
            "comments",
        ),
    )
)
