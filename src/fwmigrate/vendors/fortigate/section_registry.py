"""Declarative FortiGate source field metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


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

    declared_fields: frozenset[str] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "declared_fields",
            (
                self.list_fields
                | self.integer_fields
                | self.integer_list_fields
                | self.scalar_fields
            ),
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
            "vdom",
            "type",
            "mode",
            "ip",
            "interface",
            "alias",
            "description",
            "status",
            "role",
            "dedicated-to",
            "mtu-override",
            "dhcp-relay-service",
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
        source_path="system interface ipv6",
        list_fields=_fields("ip6-allowaccess"),
        integer_fields=_fields("ip6-default-life"),
        scalar_fields=_fields(
            "ip6-mode",
            "ip6-address",
            "ip6-send-adv",
            "ip6-manage-flag",
            "ip6-other-flag",
            "ip6-dns-server-override",
            "dhcp6-prefix-delegation",
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

register_section(
    SectionSpec(
        source_path="system session-helper",
        integer_fields=_fields("id", "port", "protocol"),
        scalar_fields=_fields("name"),
    )
)

register_section(SectionSpec(
    source_path="vpn ssl web realm",
    integer_fields=_fields("max-concurrent-user", "radius-port"),
    scalar_fields=_fields("login-page", "nas-ip", "radius-server", "url-path", "virtual-host", "virtual-host-only", "virtual-host-server-cert"),
))

register_section(SectionSpec(
    source_path="vpn ssl client",
    integer_fields=_fields("class-id", "distance", "port", "priority"),
    scalar_fields=_fields("certificate", "comment", "interface", "ipv4-subnets", "ipv6-subnets", "peer", "realm", "server", "source-ip", "status", "user"),
))

register_section(SectionSpec(source_path="vpn ssl web user-bookmark", scalar_fields=_fields("custom-lang")))
register_section(SectionSpec(source_path="vpn ssl web user-group-bookmark", scalar_fields=_fields("custom-lang")))
for _path in ("vpn ssl web user-bookmark bookmarks", "vpn ssl web user-group-bookmark bookmarks"):
    register_section(SectionSpec(
        source_path=_path,
        integer_fields=_fields("height", "port", "preconnection-id", "width"),
        scalar_fields=_fields("additional-params", "apptype", "color-depth", "description", "domain", "folder", "host", "keyboard-layout", "load-balancing-info", "logon-user", "preconnection-blob", "restricted-admin", "security", "send-preconnection-id", "sso", "sso-credential", "sso-credential-sent-once", "sso-username", "url", "vnc-keyboard-layout"),
    ))
for _path in ("vpn ssl web user-bookmark bookmarks form-data", "vpn ssl web user-group-bookmark bookmarks form-data"):
    register_section(SectionSpec(source_path=_path, scalar_fields=_fields("value")))

register_section(SectionSpec(
    source_path="user nac-policy", list_fields=_fields("severity", "switch-group"),
    integer_fields=_fields("match-period"),
    scalar_fields=_fields("category", "description", "ems-tag", "family", "firewall-address", "fortivoice-tag", "host", "hw-vendor", "hw-version", "mac", "match-type", "os", "src", "ssid-policy", "status", "sw-version", "switch-fortilink", "switch-mac-policy", "type", "user", "user-group"),
))
register_section(SectionSpec(
    source_path="firewall address6-template", integer_fields=_fields("subnet-segment-count"),
    scalar_fields=_fields("fabric-object", "ip6"),
))
register_section(SectionSpec(source_path="firewall address6-template subnet-segment", integer_fields=_fields("bits"), scalar_fields=_fields("exclusive", "name")))
register_section(SectionSpec(source_path="firewall address6-template subnet-segment values", scalar_fields=_fields("value")))
register_section(SectionSpec(source_path="ips settings", integer_fields=_fields("ips-packet-quota", "packet-log-history")))
register_section(SectionSpec(source_path="router setting", scalar_fields=_fields("hostname", "show-filter")))
register_section(SectionSpec(source_path="vpn kmip-server", integer_fields=_fields("source-port"), scalar_fields=_fields("interface", "interface-select-method", "server-identity-check", "source-ip", "ssl-min-proto-version", "username")))
register_section(SectionSpec(source_path="vpn kmip-server server-list", integer_fields=_fields("port"), scalar_fields=_fields("cert", "server", "status")))
register_section(SectionSpec(source_path="user krb-keytab", list_fields=_fields("ldap-server"), scalar_fields=_fields("pac-data", "principal")))
register_section(SectionSpec(source_path="system sdn-proxy", integer_fields=_fields("server-port"), scalar_fields=_fields("server", "type", "username")))
register_section(SectionSpec(source_path="firewall on-demand-sniffer", list_fields=_fields("ports", "protocols"), integer_fields=_fields("max-packet-count"), scalar_fields=_fields("advanced-filter", "hosts", "interface", "non-ip-packet")))
register_section(SectionSpec(source_path="system affinity-interrupt", scalar_fields=_fields("affinity-cpumask", "default-affinity-cpumask", "interrupt")))
register_section(SectionSpec(source_path="system serial-port"))
register_section(SectionSpec(source_path="firewall region", list_fields=_fields("city"), scalar_fields=_fields("name")))
register_section(SectionSpec(source_path="firewall vendor-mac", integer_fields=_fields("mac-number", "obsolete"), scalar_fields=_fields("name")))

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

register_section(SectionSpec(
    source_path="firewall central-snat-map",
    list_fields=_fields("srcintf", "dstintf", "orig-addr", "orig-addr6", "dst-addr", "dst-addr6", "nat-ippool", "nat-ippool6"),
    integer_fields=_fields("protocol"),
    scalar_fields=_fields("orig-port", "dst-port", "nat-port", "port-preserve", "nat", "nat46", "nat64", "status", "type", "uuid", "comments"),
))

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
            "nat64",
            "nat46",
            "natinbound",
            "natoutbound",
            "natip",
            "ippool",
            "fixedport",
            "port-preserve",

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
            "profile-protocol-options",
            "per-ip-shaper",

            "av-profile",
            "ips-sensor",
            "application-list",
            "webfilter-profile",
            "dnsfilter-profile",
            "ssl-ssh-profile",
            "file-filter-profile",
            "emailfilter-profile",
            "waf-profile",

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

register_section(
    SectionSpec(
        source_path="firewall security-policy",
        integer_list_fields=_fields("app-category"),
        scalar_fields=_fields("action"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall profile-protocol-options",
        scalar_fields=_fields("comment", "oversize-log", "replacemsg-group", "rpc-over-http", "switching-protocols-log"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall shaper per-ip-shaper",
        integer_fields=_fields("max-bandwidth", "max-concurrent-session", "max-concurrent-tcp-session", "max-concurrent-udp-session"),
        scalar_fields=_fields("bandwidth-unit", "diffserv-forward", "diffserv-reverse", "diffservcode-forward", "diffservcode-rev"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall vip6",
        list_fields=_fields("monitor"),
        integer_fields=_fields("color", "http-cookie-age", "http-cookie-generation", "id", "max-embryonic-connections"),
        scalar_fields=_fields(
            "add-nat64-route", "comment", "embedded-ipv4-address", "extip", "extport",
            "http-cookie-domain", "http-cookie-domain-from-host", "http-cookie-path", "http-cookie-share",
            "http-ip-header", "http-ip-header-name", "http-multiplex", "http-redirect", "https-cookie-secure",
            "ipv4-mappedip", "ipv4-mappedport", "ldb-method", "mappedip", "mappedport",
            "nat-source-vip", "nat64", "nat66", "ndp-reply", "outlook-web-access", "persistence",
            "portforward", "protocol",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall vipgrp6",
        list_fields=_fields("member"),
        integer_fields=_fields("color"),
        scalar_fields=_fields("comments", "uuid"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall ippool6",
        scalar_fields=_fields("add-nat46-route", "comments", "endip", "nat46", "startip"),
    )
)

register_section(
    SectionSpec(
        source_path="router static6",
        list_fields=_fields("sdwan-zone"),
        integer_fields=_fields("devindex", "distance", "priority", "vrf", "weight"),
        scalar_fields=_fields(
            "bfd", "blackhole", "comment", "device", "dst", "dstaddr",
            "dynamic-gateway", "gateway", "link-monitor-exempt", "status",
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
        source_path="vpn ipsec phase1",
        list_fields=_fields("proposal", "certificate"),
        integer_fields=_fields("keylife", "distance", "priority", "client-resume-interval"),
        integer_list_fields=_fields("dhgrp"),
        scalar_fields=_fields(
            "type", "interface", "local-gw", "remote-gw", "remotegw-ddns", "ike-version",
            "authmethod", "authmethod-remote", "mode", "nattraversal", "dpd", "dpd-retrycount",
            "dpd-retryinterval", "localid", "localid-type", "peerid", "comments", "psksecret",
            "psksecret-remote", "ppk-secret", "authpasswd", "group-authentication-secret",
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
            "src-subnet6",
            "src-start-ip6",
            "src-end-ip6",
            "src-name6",
            "dst-addr-type",
            "dst-subnet",
            "dst-start-ip",
            "dst-end-ip",
            "dst-name",
            "dst-subnet6",
            "dst-start-ip6",
            "dst-end-ip6",
            "dst-name6",
            "replay",
            "auto-negotiate",
            "comments",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="vpn ipsec phase2",
        list_fields=_fields("proposal"),
        integer_fields=_fields("keylifeseconds", "keylifekbs", "protocol", "src-port", "dst-port"),
        integer_list_fields=_fields("dhgrp"),
        scalar_fields=_fields(
            "phase1name", "add-route", "auto-negotiate", "comments", "dhcp-ipsec", "diffserv",
            "diffservcode", "dst-addr-type", "dst-end-ip", "dst-end-ip6", "dst-name", "dst-name6",
            "dst-start-ip", "dst-start-ip6", "dst-subnet", "dst-subnet6", "encapsulation",
            "inbound-dscp-copy", "initiator-ts-narrow", "ipv4-df", "keepalive", "keylife-type", "l2tp",
            "pfs", "replay", "route-overlap", "src-addr-type", "src-end-ip", "src-end-ip6", "src-name",
            "src-name6", "src-start-ip", "src-start-ip6", "src-subnet", "src-subnet6",
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


# ----------------------------------------------------------------------
# System / HA / SNMP / DNS / NTP / FortiGuard
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="system global",
        integer_fields=_fields(
            "admin-port", "admin-sport", "admin-ssh-port", "admin-telnet-port",
            "admintimeout", "admin-lockout-threshold", "admin-lockout-duration",
            "dh-params", "ldapconntimeout", "remoteauthtimeout",
        ),
        scalar_fields=_fields(
            "hostname", "alias", "timezone", "gui-theme", "admin-https-redirect",
            "admin-ssh-v1", "admin-scp", "admin-server-cert", "admin-login-max",
            "forticloud-account-enforcement", "admin-password-policy",
            "password-policy-scope", "management-mode", "switch-controller",
            "wireless-mode", "vdom-mode", "vdom-Admin", "internal-switch-mode",
            "cfg-save", " revision-backup-on-logout", "revision-backup-on-logout",
            "pre-login-banner", "post-login-banner", "language",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system dns",
        list_fields=_fields("domain", "interface"),
        integer_fields=_fields("dns-cache-limit", "dns-cache-ttl", "retry", "timeout"),
        scalar_fields=_fields(
            "primary", "secondary", "protocol", "ssl-certificate", "server-hostname",
            "ip6-primary", "ip6-secondary", "source-ip", "interface-select-method",
            "dns-over-tls",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system ntp",
        list_fields=_fields("interface"),
        integer_fields=_fields("syncinterval"),
        scalar_fields=_fields(
            "ntpsync", "type", "server-mode", "source-ip", "source-ip6", "authentication",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system ntp ntpserver",
        integer_fields=_fields("key-id"),
        scalar_fields=_fields(
            "server", "ntpv3", "authentication", "interface", "interface-select-method",
            "ip-type",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system ha",
        list_fields=_fields("monitor", "pingserver-monitor-interface", "secondary-vcluster"),
        integer_fields=_fields(
            "group-id", "priority", "hb-interval", "hb-lost-threshold",
            "hello-holddown", "arps", "arps-interval", "sync-packet-balance",
            "weight", "cpu-threshold", "memory-threshold",
        ),
        scalar_fields=_fields(
            "mode", "group-name", "hbdev", "session-pickup", "session-pickup-connectionless",
            "session-pickup-expectation", "session-pickup-nat", "session-pickup-delay",
            "override", "override-wait-time", "schedule", "load-balance-all",
            "ha-mgmt-status", "ha-direct", "unicast-hb", "unicast-hb-peerip",
            "unicast-hb-netmask", "encryption", "authentication", "route-ttl",
            "route-wait", "route-hold", "multicast-ttl", "link-failed-signal",
            "standalone-mgmt-vdom", " standalone-config-sync", "standalone-config-sync",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system ha ha-mgmt-interfaces",
        scalar_fields=_fields("interface", "gateway", "gateway6", "dst"),
    )
)

register_section(
    SectionSpec(
        source_path="system snmp sysinfo",
        integer_fields=_fields("trap-high-cpu-threshold", "trap-low-memory-threshold", "trap-log-full-threshold"),
        scalar_fields=_fields("status", "description", "location", "contact-info", "engine-id"),
    )
)

register_section(
    SectionSpec(
        source_path="system snmp community",
        list_fields=_fields("events"),
        integer_fields=_fields("query-v1-port", "query-v2c-port", "trap-v1-lport", "trap-v1-rport", "trap-v2c-lport", "trap-v2c-rport"),
        scalar_fields=_fields(
            "name", "status", "query-v1-status", "query-v2c-status",
            "trap-v1-status", "trap-v2c-status", "mib-view", "vdoms",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system snmp community hosts",
        scalar_fields=_fields("ip", "source-ip", "ha-direct", "host-type", "interface", "interface-select-method"),
    )
)

register_section(
    SectionSpec(
        source_path="system snmp user",
        list_fields=_fields("events", "notify-hosts", "notify-hosts6"),
        integer_fields=_fields("notify-port"),
        scalar_fields=_fields(
            "status", "security-level", "auth-proto", "priv-proto", "queries",
            "query-port", "source-ip", "source-ipv6", "ha-direct", "mib-view", "vdoms",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system fortiguard",
        integer_fields=_fields("port", "webfilter-cache-ttl", "webfilter-timeout", "antispam-cache-ttl", "antispam-timeout", "auto-join-forticloud"),
        scalar_fields=_fields(
            "fortiguard-anycast", "fortiguard-anycast-source", "protocol",
            "service-account-id", "load-balance-servers", "update-server-location",
            "sandbox-region", "webfilter-sdns-server-ip", "webfilter-sdns-Server-port",
            "webfilter-cache", "antispam-cache", "outbreak-prevention-cache",
            "source-ip", "source-ip6", "interface", "interface-select-method",
            "ddns-server-ip", "ddns-server-port",
        ),
    )
)


# ----------------------------------------------------------------------
# Dynamic Routing & Multicast
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="router bgp",
        integer_fields=_fields(
            "as", "keepalive-timer", "holdtime-timer", "distance-external",
            "distance-internal", "distance-local", "graceful-restart-time",
            "graceful-stalepath-time", "graceful-update-delay", "scan-time",
        ),
        scalar_fields=_fields(
            "router-id", "ebgp-multipath", "ibgp-multipath", "additional-path",
            "additional-path6", "graceful-restart", "always-compare-med",
            "deterministic-med", "bestpath-as-path-ignore", "bestpath-cmp-routerid",
            "bestpath-med-confed", "bestpath-med-missing-as-worst",
            "client-to-client-reflection", "ederation-identifier", "confederation-identifier",
            "enforce-first-as", "fast-external-failover", "log-neighbour-changes",
            "network-import-check", "Synchronization", "synchronization", "tag-resolve-mode",
        ),
    )
)

for _bgp_nb_path in ("router bgp neighbor", "router bgp neighbor-group"):
    register_section(
        SectionSpec(
            source_path=_bgp_nb_path,
            integer_fields=_fields(
                "remote-as", "local-as", "keep-alive-timer", "holdtime-timer",
                "connect-timer", "weight", "ebgp-multihop-ttl", "advertisement-interval",
                "allowas-in", "allowas-in6", "maximum-prefix", "maximum-prefix6",
                "default-originate-routemap",
            ),
            scalar_fields=_fields(
                "ip", "interface", "update-source", "description", "shutdown",
                "bfd", "ebgp-enforce-multihop", "next-hop-self", "next-hop-self6",
                "route-reflector-client", "route-reflector-client6", "soft-reconfiguration",
                "soft-reconfiguration6", "capability-default-originate",
                "capability-default-originate6", "capability-graceful-restart",
                "capability-graceful-restart6", "route-map-in", "route-map-out",
                "route-map-in6", "route-map-out6", "prefix-list-in", "prefix-list-out",
                "prefix-list-in6", "prefix-list-out6", "filter-list-in", "filter-list-out",
                "distribute-list-in", "distribute-list-out", "neighbor-group",
                "passive", "remove-private-as", "remove-private-as6", "as-override",
                "attribute-unchanged", "activate", "activate6", "additional-path",
                "additional-path6",
            ),
        )
    )

for _bgp_net_path in ("router bgp network", "router bgp network6"):
    register_section(
        SectionSpec(
            source_path=_bgp_net_path,
            scalar_fields=_fields("prefix", "prefix6", "route-map", "backdoor", "network-import-check"),
        )
    )

for _bgp_redist_path in ("router bgp redistribute", "router bgp redistribute6"):
    register_section(
        SectionSpec(
            source_path=_bgp_redist_path,
            scalar_fields=_fields("status", "route-map"),
        )
    )

register_section(
    SectionSpec(
        source_path="router ospf",
        integer_fields=_fields("distance", "distance-external", "distance-inter-area", "distance-intra-area", "default-information-metric", "auto-cost-ref-bandwidth"),
        scalar_fields=_fields(
            "router-id", "default-information-originate", "default-information-metric-type",
            "default-information-route-map", "abr-type", "rfc1583-compatible",
            "log-neighbour-changes", "bfd", "restart-mode",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="router ospf area",
        integer_fields=_fields("default-cost"),
        scalar_fields=_fields("type", "authentication", "shortcut", "nssa-translator-role", "nssa-default-information-originate"),
    )
)

register_section(
    SectionSpec(
        source_path="router ospf ospf-interface",
        integer_fields=_fields("cost", "priority", "hello-interval", "dead-interval", "retransmit-interval", "transmit-delay", "mtu"),
        scalar_fields=_fields("interface", "ip", "authentication", "network-type", "bfd", "status", "mtu-ignore"),
    )
)

register_section(
    SectionSpec(
        source_path="router ospf network",
        scalar_fields=_fields("prefix", "area", "comments"),
    )
)

register_section(
    SectionSpec(
        source_path="router ospf redistribute",
        integer_fields=_fields("metric", "tag"),
        scalar_fields=_fields("status", "metric-type", "routemap"),
    )
)

register_section(
    SectionSpec(
        source_path="router ospf6",
        integer_fields=_fields("default-information-metric", "auto-cost-ref-bandwidth"),
        scalar_fields=_fields("router-id", "default-information-originate", "default-information-metric-type", "default-information-route-map", "abr-type", "log-neighbour-changes", "bfd"),
    )
)

register_section(
    SectionSpec(
        source_path="router rip",
        integer_fields=_fields("default-metric", "update-timer", "timeout-timer", "garbage-timer", "max-out-metric"),
        scalar_fields=_fields("version", "default-information-originate", "recv-buffer-size"),
    )
)

for _pbr_path in ("router policy", "router policy6"):
    register_section(
        SectionSpec(
            source_path=_pbr_path,
            list_fields=_fields("input-device", "src", "srcaddr", "dst", "dstaddr", "internet-service-id", "internet-service-custom"),
            integer_fields=_fields("protocol", "start-port", "end-port", "start-source-port", "end-source-port", "tos", "tos-mask"),
            scalar_fields=_fields(
                "input-device-negate", "src-negate", "dst-negate", "action",
                "gateway", "output-device", "status", "comments",
            ),
        )
    )

for _pfx_path in ("router prefix-list", "router prefix-list6"):
    register_section(
        SectionSpec(
            source_path=_pfx_path,
            scalar_fields=_fields("comments"),
        )
    )
    register_section(
        SectionSpec(
            source_path=f"{_pfx_path} rule",
            integer_fields=_fields("ge", "le", "flags"),
            scalar_fields=_fields("action", "prefix", "prefix6"),
        )
    )

register_section(
    SectionSpec(
        source_path="router route-map",
        scalar_fields=_fields("comments"),
    )
)

register_section(
    SectionSpec(
        source_path="router route-map rule",
        integer_fields=_fields("match-metric", "match-tag", "match-vrf", "set-local-preference", "set-metric", "set-origin-as", "set-tag", "set-weight"),
        scalar_fields=_fields(
            "action", "match-as-path", "match-community", "match-community-exact",
            "match-interface", "match-ip-address", "match-ip-nexthop",
            "match-ip6-address", "match-ip6-nexthop", "match-origin", "match-route-type",
            "set-aggregator-as", "set-aggregator-ip", "set-aspath", "set-aspath-action",
            "set-atomic-aggregate", "set-community", "set-community-additive",
            "set-community-delete", "set-dampening-max-suppress", "set-extcommunity-rt",
            "set-extcommunity-soo", "set-ip-nexthop", "set-ip6-nexthop",
            "set-ip6-nexthop-local", "set-metric-type", "set-origin",
            "set-Originator-id", "set-originator-id", "set-route-tag",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="router aspath-list",
        scalar_fields=_fields("name"),
    )
)

register_section(
    SectionSpec(
        source_path="router aspath-list rule",
        scalar_fields=_fields("action", "regexp"),
    )
)

register_section(
    SectionSpec(
        source_path="router community-list",
        scalar_fields=_fields("type", "name"),
    )
)

register_section(
    SectionSpec(
        source_path="router community-list rule",
        scalar_fields=_fields("action", "match", "regexp"),
    )
)

register_section(
    SectionSpec(
        source_path="router multicast",
        integer_fields=_fields("route-limit", "route-threshold"),
        scalar_fields=_fields("multicast-routing"),
    )
)

register_section(
    SectionSpec(
        source_path="router multicast interface",
        integer_fields=_fields("dr-priority", "hello-interval", "hello-holdtime", "igmp-version", "ttl-threshold"),
        scalar_fields=_fields("pim-mode", "passive", "multicast-flow", "static-group", "rpf-nbr-fail-back"),
    )
)

register_section(
    SectionSpec(
        source_path="system ipam",
        scalar_fields=_fields("status", "server-type", "pool-subnet", "manage-lan-addresses", "manage-lan-extension-addresses", "manage-ssid-addresses"),
    )
)

register_section(
    SectionSpec(
        source_path="extender-controller extender",
        integer_fields=_fields("id", "quota-limit", "billing-start-day"),
        scalar_fields=_fields(
            "name", "sn", "authorized", "admin", "ext-name", "description",
            "role", "mode", "wan-extension", "lan-extension", "device-id",
            "extension-type", "profile", "override-allowaccess", "login-password-change",
        ),
    )
)


# ----------------------------------------------------------------------
# Extended Policies, Shapers & Load Balance Monitors
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="firewall proxy-policy",
        list_fields=_fields(
            "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
            "service", "groups", "users", "poolname", "internet-service-name",
            "internet-service-group", "internet-service-custom", "access-proxy",
            "access-proxy6",
        ),
        scalar_fields=_fields(
            "uuid", "name", "proxy", "status", "action", "schedule", "logtraffic",
            "logtraffic-start", "comments", "utm-status", "profile-type",
            "profile-group", "profile-protocol-options", "av-profile", "webfilter-profile",
            "emailfilter-profile", "dlp-profile", "file-filter-profile", "ips-sensor",
            "application-list", "icap-profile", "cifs-profile", "waf-profile",
            "ssh-filter-profile", "ssl-ssh-profile", "replacemsg-override-group",
            "transparent", "webcache", "webcache-https", "http-tunnel-auth",
            "srcaddr-negate", "dstaddr-negate", "service-negate", "internet-service",
            "disclaimer", "redirect-url", "decryption-traffic-mirror",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall auth-policy",
        list_fields=_fields("srcintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "groups", "users"),
        scalar_fields=_fields(
            "name", "status", "service", "comments", "active-auth-method",
            "sso-auth-method", "web-auth-cookie", "http-auth-type",
            "srcaddr-negate", "dstaddr-negate",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall shaper traffic-shaper",
        integer_fields=_fields("guaranteed-bandwidth", "maximum-bandwidth", "overhead", "cos-marking-method"),
        scalar_fields=_fields(
            "bandwidth-unit", "priority", "per-policy", "diffserv", "diffservcode",
            "dscp-marking-method", "exceed-bandwidth", "exceed-dscp", "maximum-dscp",
            "cos", "exceed-cos", "maximum-cos",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="firewall ldb-monitor",
        integer_fields=_fields("interval", "timeout", "retry", "port", "http-max-redirects"),
        scalar_fields=_fields(
            "type", "src-ip", "http-get", "http-match", "dns-protocol",
            "dns-request-domain", "dns-match-ip",
        ),
    )
)


# ----------------------------------------------------------------------
# Security Profiles (Antivirus, WebFilter, DNSFilter, AppControl, File, Email, VoIP, WAF, SSL/SSH)
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="antivirus profile",
        scalar_fields=_fields(
            "comment", "feature-set", "inspection-mode", "ftgd-analytics",
            "analytics-db", "mobile-malware-db", "av-virus-log", "av-block-log",
            "extended-log", "scan-mode", "replacemsg-group", "ems-threat-feed",
            "outbreak-prevention", "outbreak-prevention-archive-scan",
        ),
    )
)

for _av_proto in ("http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "cifs", "ssh"):
    register_section(
        SectionSpec(
            source_path=f"antivirus profile {_av_proto}",
            list_fields=_fields("archive-block", "archive-log"),
            scalar_fields=_fields(
                "av-scan", "options", "outbreak-prevention", "quarantine",
                "emulator", "executables", "external-blocklist", "content-disarm",
            ),
        )
    )

register_section(
    SectionSpec(
        source_path="webfilter profile",
        list_fields=_fields("options"),
        scalar_fields=_fields(
            "comment", "feature-set", "inspection-mode", "replacemsg-group",
            "ovrd-perm", "post-action", "log-all-url", "web-content-log",
            "web-filter-activex-log", "web-filter-command-block-log",
            "web-filter-cookie-log", "web-filter-applet-log", "web-filter-jscript-log",
            "web-filter-js-log", "web-filter-vbs-log", "web-filter-unknown-log",
            "web-filter-referer-log", "web-filter-script-log", "web-url-log",
            "web-invalid-domain-log", "web-ftgd-err-log", "web-ftgd-quota-usage",
            "extended-log", "wisp", "wisp-algorithm", "https-replacemsg",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter profile web",
        list_fields=_fields("safe-search"),
        integer_fields=_fields("urlfilter-table", "bword-table", "bword-threshold", "content-header-list"),
        scalar_fields=_fields(
            "block-invalid-url", "blacklist", "whitelist", "allowlist",
            "youtube-restrict", "vimeo-restrict", "log-search", "keyword-match",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter profile ftgd-wf",
        list_fields=_fields("options", "ovrd"),
        integer_fields=_fields("max-quota-timeout", "rate-crl-urls", "rate-css-urls", "rate-image-urls", "rate-javascript-urls"),
        scalar_fields=_fields("exempt-quota"),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter profile ftgd-wf filters",
        list_fields=_fields("auth-usr-grp"),
        integer_fields=_fields("category"),
        scalar_fields=_fields("action", "log", "warning-prompt", "warn-duration", "override-replacemsg"),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter urlfilter",
        scalar_fields=_fields("name", "comment", "one-arm-ips-urlfilter", "ip-addr-block", "ip4-mapped-ip6"),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter urlfilter entries",
        scalar_fields=_fields(
            "url", "type", "action", "status", "exempt", "web-proxy-profile",
            "referrer-host", "dns-address-family", "antiphish-action",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter ftgd-local-cat",
        integer_fields=_fields("id"),
        scalar_fields=_fields("status", "desc"),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter ftgd-local-rating",
        integer_list_fields=_fields("rating"),
        scalar_fields=_fields("status", "comment"),
    )
)

register_section(
    SectionSpec(
        source_path="webfilter override",
        integer_fields=_fields("id"),
        scalar_fields=_fields(
            "status", "user", "user-group", "ip", "ip6", "new-profile",
            "old-profile", "scope", "expires", "initiator",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="dnsfilter profile",
        list_fields=_fields("external-ip-blocklist", "transparent-dns-database"),
        scalar_fields=_fields(
            "comment", "block-action", "redirect-portal", "redirect-portal6",
            "block-botnet", "safe-search", "youtube-restrict", "log-all-domain",
            "sdns-ftgd-err-log", "sdns-domain-log", "strip-ech",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="dnsfilter profile ftgd-dns",
        list_fields=_fields("options"),
    )
)

register_section(
    SectionSpec(
        source_path="dnsfilter profile ftgd-dns filters",
        integer_fields=_fields("category"),
        scalar_fields=_fields("action", "log"),
    )
)

register_section(
    SectionSpec(
        source_path="dnsfilter profile domain-filter",
        integer_fields=_fields("domain-filter-table"),
    )
)

register_section(
    SectionSpec(
        source_path="application list",
        list_fields=_fields("options"),
        scalar_fields=_fields(
            "comment", "other-application-action", "other-application-log",
            "unknown-application-action", "unknown-application-log",
            "enforce-default-app-port", "default-network-services",
            "deep-app-inspection", "extended-log", "replacemsg-group",
            "control-default-network-services",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="application list entries",
        integer_list_fields=_fields("category", "application", "risk", "popularity"),
        list_fields=_fields("protocols", "vendor", "technology", "behavior", "quarantine-ita"),
        scalar_fields=_fields(
            "action", "log", "log-packet", "per-ip-shaper", "session-ttl",
            "shaper", "shaper-reverse", "quarantine", "quarantine-expiry",
            "quarantine-log", "sub-category",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="file-filter profile",
        scalar_fields=_fields(
            "comment", "feature-set", "replacemsg-group", "log",
            "extended-log", "scan-archive-contents",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="file-filter profile rules",
        list_fields=_fields("protocol", "file-type"),
        scalar_fields=_fields("name", "comment", "action", "direction", "password-protected"),
    )
)

register_section(
    SectionSpec(
        source_path="emailfilter profile",
        list_fields=_fields("options"),
        integer_fields=_fields("spam-bword-table", "spam-bword-threshold", "spam-bwl-table", "spam-mheader-table", "spam-ipbwl-table", "spam-iptrust-table"),
        scalar_fields=_fields(
            "comment", "feature-set", "replacemsg-group", "spam-filtering",
            "spam-log", "spam-log-fortiguard-response", "external",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="voip profile",
        scalar_fields=_fields("comment", "feature-set"),
    )
)

register_section(
    SectionSpec(
        source_path="voip profile sip",
        integer_fields=_fields("invite-rate", "register-rate", "max-dialogs", "max-idle-dialogs"),
        scalar_fields=_fields(
            "status", "rtp", "open-register-pinhole", "open-contact-pinhole",
            "open-via-pinhole", "open-record-route-pinhole", "strict-register",
            "block-unk", "block-long-lines", "log-violations", "log-call-summary",
            "nat-trace", "ips-rtp",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="waf profile",
        scalar_fields=_fields("comment", "extended-log", "external", "replacemsg-group"),
    )
)

register_section(
    SectionSpec(
        source_path="firewall ssl-ssh-profile",
        list_fields=_fields("untrusted-caname"),
        scalar_fields=_fields(
            "comment", "caname", "server-cert-mode", "server-cert",
            "use-ssl-server", "ssl-exemption-ip-rating", "ssl-exemption-log",
            "ssl-anomaly-log", "ssl-negotiation-log", "ssl-server-cert-log",
            "ssl-handshake-log", "rpc-over-http", "mapi-over-https",
            "supported-alpn", "ech-outer-sni",
        ),
    )
)

for _ssl_proto in ("https", "ftps", "imaps", "pop3s", "smtps", "ssl", "dot"):
    register_section(
        SectionSpec(
            source_path=f"firewall ssl-ssh-profile {_ssl_proto}",
            integer_list_fields=_fields("ports"),
            scalar_fields=_fields(
                "status", "client-certificate", "unsupported-ssl-cipher",
                "unsupported-ssl-negotiation", "unsupported-ssl-version",
                "expired-server-cert", "revoked-server-cert", "untrusted-server-cert",
                "cert-validation-timeout", "cert-validation-failure",
                "sni-server-cert-check", "min-allowed-ssl-version",
                "quic", "proxy-after-tcp-handshake",
            ),
        )
    )

register_section(
    SectionSpec(
        source_path="firewall ssl-ssh-profile ssh",
        integer_list_fields=_fields("ports"),
        list_fields=_fields("inspect-all", "block", "log"),
        scalar_fields=_fields(
            "status", "unsupported-version", "ssh-tun-policy-check",
            "ssh-policy-check", "proxy-after-tcp-handshake",
        ),
    )
)


# ----------------------------------------------------------------------
# User & Auth Extensions (LDAP, RADIUS, TACACS+, FSSO, FortiToken, Settings)
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="user ldap",
        integer_fields=_fields("port", "account-key-upn-san"),
        scalar_fields=_fields(
            "server", "secondary-server", "tertiary-server", "server-identity-check",
            "cnid", "dn", "type", "username", "group-member-check", "group-search-base",
            "group-object-filter", "group-filter", "secure", "ca-cert", "client-cert",
            "client-cert-auth", "member-attr", "account-key-processing", "account-key-filter",
            "source-ip", "source-port", "interface", "interface-select-method",
            "two-factor", "two-factor-authentication", "two-factor-notification",
            "two-factor-filter", "password-expiry-warning", "password-renewal",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user radius",
        list_fields=_fields("class"),
        integer_fields=_fields("timeout", "radius-port", "acct-interim-interval"),
        scalar_fields=_fields(
            "server", "secondary-server", "tertiary-server", "auth-type",
            "nas-ip", "nas-ip6", "nas-id", "nas-id-type", "all-usergroup",
            "use-management-vdom", "sso-attribute", "sso-attribute-key",
            "rsso", "rsso-radius-server-port", "rsso-radius-response",
            "rsso-validate-request-secret", "source-ip", "source-ip6",
            "interface", "interface-select-method", "h3c-compatibility",
            "password-renewal", "password-encoding", "acct-all-servers",
            "switch-controller-acct-fast-framedip-detect", "transport-protocol",
            "ca-cert", "client-cert", "tls-min-proto-version", "server-identity-check",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user tacacs+",
        integer_fields=_fields("port"),
        scalar_fields=_fields(
            "server", "secondary-server", "tertiary-server", "authen-type",
            "authorization", "source-ip", "interface", "interface-select-method",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user fsso",
        integer_fields=_fields("port", "port2", "port3", "port4", "port5", "group-poll-interval"),
        scalar_fields=_fields(
            "server", "server2", "server3", "server4", "server5",
            "ldap-server", "ldap-poll", "ldap-poll-interval", "ldap-poll-filter",
            "user-info-server", "ssl", "ssl-trusted-cert", "ssl-server-host-ip-check",
            "source-ip", "source-ip6", "interface", "interface-select-method",
            "type", "logon-timeout",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user fsso-polling",
        integer_fields=_fields("poll-frequency", "port"),
        scalar_fields=_fields(
            "status", "server", "default-domain", "user", "ldap-server",
            "logon-history", "smb-ntlmv1-auth", "smbv1",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user fortitoken",
        integer_fields=_fields("activation-expire"),
        scalar_fields=_fields(
            "status", "comments", "license", "os-ver", "reg-id",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user setting",
        integer_fields=_fields("auth-timeout", "auth-portal-timeout", "auth-Blackout-time", "auth-blackout-time"),
        scalar_fields=_fields(
            "auth-type", "auth-cert", "auth-ca-cert", "auth-secure-http",
            "auth-http-basic", "auth-ssl-allow-renegotiation", "auth-timeout-type",
            "auth-invalid-max", "auth-lockout-threshold", "auth-lockout-duration",
            "per-policy-disclaimer", "radius-ses-timeout-act", "auth-on-demand",
            "auth-ssl-min-proto-version", "auth-ssl-max-proto-version",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="user password-policy",
        integer_fields=_fields("expire-days", "min-lower-case-letter", "min-upper-case-letter", "min-non-alphanumeric", "min-number", "minimum-length", "min-change-characters"),
        scalar_fields=_fields("expire-status", "warn-days", "change-4-characters", "reuse-password"),
    )
)

register_section(
    SectionSpec(
        source_path="system password-policy",
        list_fields=_fields("apply-to"),
        integer_fields=_fields("minimum-length", "min-lower-case-letter", "min-upper-case-letter", "min-non-alphanumeric", "min-number", "min-change-characters", "expire-day"),
        scalar_fields=_fields("status", "expire-status", "reuse-password"),
    )
)


# ----------------------------------------------------------------------
# WiFi, Switch & Logging
# ----------------------------------------------------------------------

register_section(
    SectionSpec(
        source_path="wireless-controller vap",
        list_fields=_fields("usergroup", "security-exempt-list", "address-group", "selected-usergroups"),
        integer_fields=_fields("vlanid", "max-clients", "max-clients-ap", "keyindex", "dtim", "rts-threshold", "frag-threshold", "pmf-assoc-come-back-timeout", "pmf-sa-query-retry-timeout"),
        scalar_fields=_fields(
            "ssid", "vdom", "status", "broadcast-ssid", "security", "encrypt",
            "auth", "radius-server", "radius-mac-auth", "radius-mac-auth-server",
            "local-standalone", "local-standalone-nat", "local-bridging",
            "local-authentication", "intra-vap-privacy", "schedule", "portal-type",
            "portal-message-override-group", "external-web", "external-logout",
            "captive-portal-ac-name", "pmf", "okc", "voice-enterprise",
            "fast-bss-transition", "eapol-key-retries", "tkip-counter-measure",
            "rates-11a", "rates-11bg", "rates-11n-ss12", "rates-11ac-ss12",
            "Dynamic-vlan", "dynamic-vlan", "vlan-pooling", "multicast-enhance",
            "igmp-snooping", "dhcp-address-enforcement", "mpsk", "mpsk-profile",
            "quarantine", "radio-sensitivity",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="wireless-controller wtp",
        integer_fields=_fields("index"),
        scalar_fields=_fields(
            "name", "wtp-id", "admin", "wtp-profile", "wtp-mode", "location",
            "comment", "login-passwd-change", "override-ip-fragment-preventing",
            "override-wan-port-mode", "wan-port-mode", "override-lan",
            "override-led-state", "led-state", "override-allowaccess",
            "allowaccess", "image-download", "mesh-bridge-enable",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="wireless-controller wtp-profile",
        list_fields=_fields("allowaccess"),
        scalar_fields=_fields(
            "comment", "login-passwd-change", "dtls-policy", "max-clients",
            "handoff-rssi", "handoff-sta-thresh", "handoff-roaming", "ap-country",
            "ip-fragment-preventing", "tun-mtu-uplink", "tun-mtu-downlink",
            "split-tunneling-acl-path", "split-tunneling-acl-local-ap-subnet",
            "energy-efficient-ethernet", "led-state", "poe-mode", "wan-port-mode",
            "lldp",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="wireless-controller wids-profile",
        scalar_fields=_fields(
            "comment", "sensor-mode", "ap-scan", "ap-scan-passive",
            "wireless-bridge", "deauth-broadcast", "null-ssid-probe-resp",
            "long-duration-attack", "invalid-mac-oui", "weak-wep-iv",
            "auth-frame-flood", "assoc-frame-flood", "reassoc-flood",
            "probe-flood", "disassoc-flood", "deauth-flood", "eapol-start-flood",
            "eapol-logoff-flood", "eapol-succ-flood", "eapol-fail-flood",
            "eapol-pre-succ-flood", "eapol-pre-fail-flood", "asleap-attack",
            "airjack", "fata-jack", "omerta", "wellenreiter", "netstumbler",
            "rogue-scan",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller managed-switch",
        integer_fields=_fields("max-allowed-trunk-members", "dynamic-capability"),
        scalar_fields=_fields(
            "name", "sn", "fsw-wan1-peer", "fsw-wan1-admin", "fsw-wan2-peer",
            "fsw-wan2-admin", "version", "poe-pre-standard-detection",
            "poe-detection-type", "directly-connected", "switch-profile",
            "override-snmp-sysinfo", "override-snmp-community", "override-snmp-user",
            "description", "type", "owner-vdom", "mclag-igmp-snooping-aware",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller managed-switch ports",
        list_fields=_fields("allowed-vlans", "untagged-vlans", "export-tags"),
        integer_fields=_fields("poe-max-power", "flap-duration", "flap-rate", "flap-timeout"),
        scalar_fields=_fields(
            "switch-id", "speed", "status", "poe-status", "poe-pre-standard-detection",
            "vlan", "allowed-vlans-all", "stp-state", "stp-root-guard", "stp-bpdu-guard",
            "edge-port", "loop-guard", "dhcp-snooping", "dhcp-snoop-learning-limit-check",
            "igmp-snooping", "igmp-fast-leave", "qos-policy", "port-security-policy",
            "mac-addr", "lldp-profile", "lldp-status", "type", "trunk", "description",
            "access-mode", "port-prefix-type", "fortilink-port",
        ),
    )
)

for _syslog_path in ("log syslogd setting", "log syslogd2 setting", "log syslogd3 setting", "log syslogd4 setting"):
    register_section(
        SectionSpec(
            source_path=_syslog_path,
            integer_fields=_fields("port", "max-log-rate"),
            scalar_fields=_fields(
                "status", "server", "mode", "facility", "source-ip", "format",
                "priority", "enc-algorithm", "ssl-min-proto-version", "certificate",
                "interface", "interface-select-method",
            ),
        )
    )

register_section(
    SectionSpec(
        source_path="log memory setting",
        scalar_fields=_fields("status", "diskfull"),
    )
)

register_section(
    SectionSpec(
        source_path="log disk setting",
        integer_fields=_fields("maximum-log-age", "upload-time", "full-first-warning-threshold", "full-second-warning-threshold", "full-final-warning-threshold", "max-log-file-size", "roll-day"),
        scalar_fields=_fields(
            "status", "ips-archive", "upload", "upload-destination", "upload-ip",
            "upload-user", "upload-folder", "upload-format", "upload-ssl-conn",
            "diskfull", "log-quota", "dlp-archive-quota", "report-quota",
            "roll-schedule", "roll-time", "interface", "interface-select-method",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="log setting",
        list_fields=_fields("custom-log-fields"),
        scalar_fields=_fields(
            "resolve-ip", "resolve-port", "log-user-in-upper", "fwpolicy-implicit-log",
            "fwpolicy6-implicit-log", "log-invalid-packet", "local-in-allow",
            "local-in-deny-unicast", "local-in-deny-broadcast", "local-out",
            "local-out-ioc-detection", "daemon-log",
            "neighbor-event", "expolicy-implicit-log", "faz-override",
            "syslog-override", "rest-api-set", "rest-api-get", "anonymization-hash",
            "brief-traffic-format", "user-anonymize",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="log threat-weight",
        scalar_fields=_fields(
            "status", "blocked-connection", "failed-connection",
            "url-block-detected", "url-block-detect", "botnet-connection-detected",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="log threat-weight level",
        integer_fields=_fields("low", "medium", "high", "critical"),
    )
)

register_section(
    SectionSpec(
        source_path="log threat-weight ips",
        scalar_fields=_fields(
            "info-severity", "low-severity", "medium-severity",
            "high-severity", "critical-severity",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="log threat-weight malware",
        scalar_fields=_fields(
            "virus-infected", "virus-file-type-executable", "virus-outbreak-prevention",
            "virus-scan-error", "botnet-connection", "command-blocked",
            "file-blocked", "oversize", "switch-proto", "mimefragmented",
            "content-disarm", "fortisandbox", "fortindr", "malware-list",
            "ems-threat-feed", "fsa-malicious", "fsa-high-risk", "fsa-medium-risk",
            "inline-block",
        ),
    )
)

for _tw_cat_path in ("log threat-weight web", "log threat-weight application"):
    register_section(
        SectionSpec(
            source_path=_tw_cat_path,
            integer_fields=_fields("category"),
            scalar_fields=_fields("level"),
        )
    )

register_section(
    SectionSpec(
        source_path="user guest",
        integer_fields=_fields("expiration"),
        scalar_fields=_fields("user-id", "type", "sponsor", "company", "email", "mobile-phone", "password", "comment"),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller port-policy",
        scalar_fields=_fields("description", "fortilink", "qos-policy", "vlan-policy", "bounce-port-link"),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller lldp-profile",
        list_fields=_fields("med-tlvs"),
        integer_fields=_fields("auto-isl-hello-timer", "auto-isl-receive-timeout", "auto-isl-port-group"),
        scalar_fields=_fields("auto-isl"),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller qos qos-policy",
        integer_fields=_fields("default-cos"),
        scalar_fields=_fields("queue-policy"),
    )
)

register_section(
    SectionSpec(
        source_path="switch-controller vlan-policy",
        list_fields=_fields("allowed-vlans", "untagged-vlans"),
        scalar_fields=_fields("description", "fortilink", "vlan", "allowed-vlans-all", "discard-mode"),
    )
)

for _cert_store in ("local", "ca", "remote"):
    register_section(
        SectionSpec(
            source_path=f"vpn certificate {_cert_store}",
            scalar_fields=_fields(
                "certificate", "ca-identifier", "comments",
                "source", "source-ip", "range", "scep-url",
            ),
        )
    )

for _local_in_path in ("firewall local-in-policy", "firewall local-in-policy6"):
    register_section(
        SectionSpec(
            source_path=_local_in_path,
            list_fields=_fields("intf", "srcaddr", "dstaddr", "service"),
            scalar_fields=_fields(
                "uuid", "srcaddr-negate", "dstaddr-negate", "action",
                "service-negate", "schedule", "status", "comments", "virtual-patch",
            ),
        )
    )

for _faz_path in (
    "log fortianalyzer setting",
    "log fortianalyzer2 setting",
    "log fortianalyzer3 setting",
):
    register_section(
        SectionSpec(
            source_path=_faz_path,
            scalar_fields=_fields(
                "status", "server", "source-ip", "upload-option", "reliable",
                "enc-algorithm", "ssl-min-proto-version", "certificate",
                "interface", "interface-select-method",
            ),
        )
    )

register_section(
    SectionSpec(
        source_path="log fortiguard setting",
        scalar_fields=_fields(
            "status", "upload-option", "upload-interval", "upload-day",
            "upload-time", "enc-algorithm", "interface", "interface-select-method",
        ),
    )
)

register_section(
    SectionSpec(
        source_path="system storage",
        integer_fields=_fields("order", "size"),
        scalar_fields=_fields("status", "media-status", "partition", "device", "usage", "wanopt-mode"),
    )
)

register_section(
    SectionSpec(
        source_path="user saml",
        scalar_fields=_fields(
            "cert", "entity-id", "single-sign-on-url", "single-logout-url",
            "idp-entity-id", "idp-single-sign-on-url", "idp-single-logout-url",
            "idp-cert", "user-name", "group-name", "digest-method",
        ),
    )
)
