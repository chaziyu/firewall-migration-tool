import re
from typing import Iterator, List, Dict, Any, Optional

from fwmigrate.parsers.fortigate.tokenizer import (
    Token,
    TokenType,
    FortiGateTokenizer,
)
from fwmigrate.parsers.fortigate.model import (
    FGConfig,
    FGSystemGlobal,
    FGInterface,
    FGInterfaceSecondaryIP,
    FGInterfaceIPv6ExtraAddress,
    FGIPv6PrefixAdvertisement,
    FGIPv6DelegatedPrefixAdvertisement,
    FGDHCPv6IAPD,
    FGInterfaceVRRP6,
    FGSystemZone,
    FGAddress,
    FGAddressListEntry,
    FGAddressTaggingEntry,
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
    FGWildcardFQDN,
    FGServiceCategory,
    FGService,
    FGServiceGroup,
    FGSchedule,
    FGTrafficShaper,
    FGProxyAddress,
    FGWebProxyGlobal,
    FGIPPool,
    FGIPPool6,
    FGVIP,
    FGVIPGroup,
    FGVIP6,
    FGVIPGroup6,
    FGVIPRealServer,
    FGPolicy,
    FGMulticastPolicy,
    FGPhase1Interface,
    FGPhase2Interface,
    FGStaticRoute,
    FGSDWan,
    FGDns,
    FGSDWanZone,
    FGSDWanMember,
    FGSDWanSLA,
    FGSDWanHealthCheck,
    FGSDWanService,
    FGSDWanServiceSLA,
    FGSDWanDuplication,
    FGSDWanNeighbor,
    FGInternetService,
    FGInternetServiceDefinition,
    FGInternetServiceDefinitionEntry,
    FGInternetServiceDefinitionPortRange,
    FGFCTEMS,
    FGSessionHelper,
    FGSessionTTLOverride,
    FGSessionTTLSettings,
    FGExecutionContext,
    FGCentralSNATRule,
    FGIPTranslation,
    FGSourceOnlyRule,
    FGScheduleGroup,
    FGDHCPServer,
    FGDHCPIPRange,
    FGDHCPExcludeRange,
    FGDHCPReservation,
    FGDHCPOption,
    FGCertificate,
    FGSSHKey,
    FGIPSSensor,
    FGIPSSensorEntry,
    FGIPSSensorExemptIP,
    FGProfileGroup,
    FGUserLDAP,
    FGFSSOServer,
    FGFSSOEndpoint,
    FGADGroup,
    FGFSSOPolling,
    FGFSSOPollingADGroup,
    FGUserSAML,
    FGLocalUser,
    FGUserGroup,
    FGUserGroupMatch,
    FGUserGroupGuest,
    FGUserAuthenticationSettings,
    FGUserQuarantine,
    FGAdministrator,
    FGAdminProfile,
    FGAdminProfilePermissionBlock,
    FGFortiToken,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
    FGSSLVPNAuthenticationRule,
    FGSSLVPNHostCheckItem,
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortalSplitDNS,
    FGSSLVPNPortalBookmarkFormData,
    FGSSLVPNPortalBookmark,
    FGSSLVPNPortalBookmarkGroup,
    FGSSLVPNPortalLandingPageFormData,
    FGSSLVPNPortalLandingPage,
    FGSSLVPNPortalMACAddressRule,
    FGSSLVPNPortalOSCheck,
    FGDoSPolicy,
    FGDoSAnomaly,
    FGFirewallSniffer,
    FGAuthenticationScheme,
    FGAuthenticationRule,
    FGNetworkServiceDynamic,
    FGSDNConnector,
    FGUserRADIUS,
    FGUserRADIUSAccountingServer,
    FGUserTACACS,
    FGLinkMonitor,
    FGTopologyObject,
    FGAccessProxy,
    FGEMSOverride,
    FGSSLVPNRealm,
    FGSSLVPNBookmark,
    FGManualKeyInterface,
)
from fwmigrate.parsers.fortigate.certificates import parse_certificate_metadata
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.source_tree import (
    FGSourceCommand,
    FGSourceNode,
    FGStructuredSourceObject,
    STRUCTURED_IDENTITY_SECTIONS,
    STRUCTURED_ROUTING_SECTIONS,
    STRUCTURED_ROUTING_DEPENDENCY_SECTIONS,
    STRUCTURED_SECURITY_SECTIONS,
    STRUCTURED_OPERATIONAL_SECTIONS,
)


SDWAN_EXPLICIT_FIELDS = {
    "system sdwan members": set(FGSDWanMember.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan health-check": set(FGSDWanHealthCheck.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan service": set(FGSDWanService.model_fields)
    - {"source_explicit_fields", "extra_settings"},
}


ROUTE_EXPLICIT_FIELDS = {
    "router static": set(FGStaticRoute.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "router static6": set(FGStaticRoute.model_fields)
    - {"source_explicit_fields", "extra_settings"},
}


SECTION_EXPLICIT_FIELDS = {
    **SDWAN_EXPLICIT_FIELDS,
    **ROUTE_EXPLICIT_FIELDS,
}


SECTION_LIST_FIELDS = {
    "user ldap": {"search_type"},
    "firewall local-in-policy": {
        "dstaddr",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_name",
        "intf",
        "service",
        "srcaddr",
    },
    "firewall local-in-policy6": {
        "dstaddr",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "intf",
        "service",
        "srcaddr",
    },
    "router policy": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "internet_service_id",
        "src",
        "srcaddr",
    },
    "router policy6": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "internet_service_id",
        "src",
        "srcaddr",
    },
    "router static": {"sdwan_zone"},
    "router static6": {"sdwan_zone"},
    "firewall addrgrp": {"member", "exclude_member"},
    "firewall addrgrp6": {"member", "exclude_member"},
    "firewall address tagging": {"tags"},
    "firewall address6 tagging": {"tags"},
    "firewall multicast-address tagging": {"tags"},
    "firewall multicast-address6 tagging": {"tags"},
    "firewall addrgrp tagging": {"tags"},
    "firewall addrgrp6 tagging": {"tags"},
    "firewall vip": {
        "extaddr", "mappedip", "monitor", "service",
        "src_filter", "srcintf_filter",
    },
    "firewall vip realservers": {"monitor"},
    "firewall vipgrp": {"member"},
    "firewall vip6": {"mappedip", "monitor", "src_filter"},
    "firewall vip6 realservers": {"monitor"},
    "firewall vipgrp6": {"member"},
    "firewall policy": {
        "custom_log_fields",
        "pcp_poolname",
        "srcintf",
        "dstintf",
        "srcaddr",
        "dstaddr",
        "service",
        "groups",
        "users",
        "poolname",
        "srcaddr6",
        "dstaddr6",
        "poolname6",
        "fsso_groups",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "internet_service_name",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_name",
        "internet_service6_custom",
        "internet_service6_custom_group",
        "internet_service6_group",
        "internet_service6_name",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "network_service_dynamic",
        "network_service_src_dynamic",
        "ntlm_enabled_browsers",
        "rtp_addr",
        "sgt",
        "src_vendor_mac",
        "ztna_ems_tag",
        "ztna_ems_tag_secondary",
        "ztna_geo_tag",
    },
    "firewall multicast-policy": {
        "srcintf", "dstintf", "srcaddr", "dstaddr", "protocol",
    },
    "firewall multicast-policy6": {
        "srcintf", "dstintf", "srcaddr", "dstaddr", "protocol",
    },
    "firewall central-snat-map": {
        "srcintf", "dstintf", "orig_addr", "orig_addr6", "dst_addr",
        "dst_addr6", "nat_ippool", "nat_ippool6",
    },
    "firewall schedule group": {"member"},
    "system admin": {"vdom", "guest_usergroups"},
    # These settings accept multiple CLI values on a system interface.  Keep
    # this section-specific because the same keys may be scalar in other
    # FortiOS sections, and because source preservation must not depend only
    # on the broad global list-field set below.
    "system interface": {
        "member",
        "fail_alert_interfaces",
        "fail_detect_option",
        "dns_server_protocol",
        "security_groups",
    },
    "system interface secondaryip": {
        "detectprotocol",
    },
    "vpn ipsec phase1-interface": {
        "proposal",
        "ipv4_split_include",
    },
    "vpn ipsec phase2-interface": {
        "proposal",
        "src_name",
        "dst_name",
        "dhgrp",
    },
    "ips sensor entries": {
        "rule",
        "severity",
        "protocol",
        "application",
        "cve",
        "os",
        "vuln_type",
    },
    "system sdwan health-check": {"members"},
    "system sdwan service": {
        "src",
        "dst",
        "health_check",
        "priority_members",
        "priority_zone",
        "internet_service_name",
        "internet_service_app_ctrl",
    },
    "system sdwan duplication": {
        "srcaddr",
        "dstaddr",
        "srcaddr6",
        "dstaddr6",
        "srcintf",
        "dstintf",
        "service",
    },
    "vpn ssl web portal": {
        "ip_pools",
        "ipv6_pools",
        "host_check_policy",
        "allow_user_access",
        "split_tunneling_routing_address",
        "ipv6_split_tunneling_routing_address",
    },
    "vpn ssl web host-check-software check-item-list": {"md5s"},
    "vpn ssl settings": {
        "banned_cipher",
        "client_sigalgs",
        "source_interface",
        "source_address",
        "source_address6",
        "tunnel_ip_pools",
        "tunnel_ipv6_pools",
    },
    "vpn ssl settings authentication-rule": {
        "groups",
        "users",
        "source_address",
        "source_address6",
        "source_interface",
    },
    "firewall DoS-policy": {"srcaddr", "dstaddr", "service"},
    "authentication rule": {"srcintf", "srcaddr"},
    "user quarantine": {"firewall_groups"},
}


FG_INTERFACE_IPV6_SCALAR_FIELDS = {
    "ip6_address",
    "ip6_mode",
    "ip6_send_adv",
    "ip6_manage_flag",
    "ip6_other_flag",
    "autoconf", "cli_conn6_status", "dhcp6_information_request", "dhcp6_prefix_delegation",
    "dhcp6_relay_interface_id", "dhcp6_relay_service",
    "dhcp6_relay_source_interface", "dhcp6_relay_source_ip", "dhcp6_relay_type",
    "icmp6_send_redirect", "interface_identifier", "ip6_default_life",
    "ip6_delegated_prefix_iaid", "ip6_dns_server_override", "ip6_hop_limit",
    "ip6_link_mtu", "ip6_max_interval", "ip6_min_interval", "ip6_prefix_mode",
    "ip6_reachable_time", "ip6_retrans_time", "ip6_subnet", "ip6_upstream_interface",
}
FG_INTERFACE_IPV6_LIST_FIELDS = {"ip6_allowaccess", "dhcp6_client_options", "dhcp6_relay_ip"}
FG_INTERFACE_IPV6_INT_FIELDS = {
    "cli_conn6_status", "ip6_default_life", "ip6_delegated_prefix_iaid", "ip6_hop_limit", "ip6_link_mtu",
    "ip6_max_interval", "ip6_min_interval", "ip6_reachable_time", "ip6_retrans_time",
}

SOURCE_ONLY_RULE_FAMILIES = {
    "firewall security-policy": "security-policy",
    "router policy": "policy-route-ipv4",
    "router policy6": "policy-route-ipv6",
    "firewall local-in-policy": "local-in-policy-ipv4",
    "firewall local-in-policy6": "local-in-policy-ipv6",
    "firewall proxy-policy": "proxy-policy",
    "firewall shaping-policy": "shaping-policy",
    "firewall shaper per-ip-shaper": "per-ip-shaper",
    "firewall shaping-profile": "shaping-profile",
    "system dhcp6 server": "dhcp6-server",
    "firewall proxy-addrgrp": "proxy-address-group",
    "vpn ipsec phase1": "ipsec-phase1-policy-mode",
    "vpn ipsec phase2": "ipsec-phase2-policy-mode",
    "vpn ipsec manualkey": "ipsec-manual-key",
    "firewall ttl-policy": "ttl-policy",
    "firewall ldb-monitor": "load-balance-monitor",
    "firewall ssl-server": "ssl-server",
    "firewall traffic-class": "traffic-class",
    "firewall wildcard-fqdn group": "wildcard-fqdn-group",
    "firewall internet-service-custom": "internet-service-custom",
    "firewall internet-service-custom-group": "internet-service-custom-group",
    "firewall acl": "acl-ipv4",
    "firewall acl6": "acl-ipv6",
    "firewall interface-policy": "interface-policy-ipv4",
    "firewall interface-policy6": "interface-policy-ipv6",
    "firewall access-proxy": "access-proxy-ipv4",
    "firewall access-proxy6": "access-proxy-ipv6",
    "vpn ipsec manualkey-interface": "ipsec-manual-key-interface",
}

CONTEXTUAL_MODEL_SECTIONS = {
    "system zone", "system interface",
    "firewall address", "firewall address6",
    "firewall multicast-address", "firewall multicast-address6",
    "firewall addrgrp", "firewall addrgrp6",
    "firewall wildcard-fqdn custom",
    "firewall service category",
    "firewall service custom", "firewall service group",
    "firewall schedule recurring", "firewall schedule onetime",
    "firewall schedule group", "firewall shaper traffic-shaper",
    "firewall proxy-address", "firewall ippool", "firewall ippool6",
    "firewall vip", "firewall vip6", "firewall vipgrp", "firewall vipgrp6",
    "firewall policy", "firewall central-snat-map", "firewall ip-translation",
    "firewall multicast-policy", "firewall multicast-policy6",
    "vpn ipsec phase1-interface", "vpn ipsec phase2-interface",
    "router static", "router static6",
    "ips sensor",
    "system dhcp server",
    "firewall DoS-policy", "firewall DoS-policy6",
    *SOURCE_ONLY_RULE_FAMILIES,
}

IDENTITY_SECTIONS = {"user ldap", "user saml", "user local", "user fsso"}
IDENTITY_SECRET_FIELDS = {
    "password",
    "password2",
    "password3",
    "password4",
    "password5",
    "passwd",
    "seed",
    "activation_code",
    "private_key",
    "ppk_secret",
}
ADMIN_SECRET_FIELDS = IDENTITY_SECRET_FIELDS | {"secret", "token", "api_key"}


def _classify_pppoe_password(values: List[str]) -> tuple[bool, Optional[str]]:
    if not values:
        return False, None
    value = " ".join(str(item) for item in values).strip()
    if not value:
        return False, None
    return True, "encrypted" if value.upper().startswith("ENC ") else "plaintext"

def _extract_extra_settings(
    attributes: Dict[str, Any],
    model_fields: set[str],
) -> Dict[str, Any]:
    """
    Remove attributes that are not represented by typed model fields
    and retain a sanitized audit copy.

    Secret-like source settings are redacted through the shared
    FortiGate source-attribute sanitizer before being preserved.
    """

    unknown_attributes = {
        key: value
        for key, value in attributes.items()
        if key not in model_fields
    }

    extra_settings = sanitize_source_attributes(
        unknown_attributes
    )

    for key in unknown_attributes:
        attributes.pop(key, None)

    return extra_settings

class ParserError(Exception):
    pass


class FortiGateParser:
    def __init__(self, tokenizer: FortiGateTokenizer):
        self.tokens = list(tokenizer.tokenize())
        self.pos = 0
        self.config = FGConfig()
        self.source_inventory_items: List[SourceInventoryItem] = []
        self.structured_source_objects: List[FGStructuredSourceObject] = []
        self.current_context = "root"
        self._source_order = 0

    def peek(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def next_token(self) -> Optional[Token]:
        token = self.peek()
        if token:
            self.pos += 1
        return token

    def _sdwan_for_current_context(self) -> FGSDWan:
        """Return the SD-WAN configuration owned by the active VDOM."""
        source_context = self.current_context or "root"
        for sdwan in self.config.sdwans:
            if sdwan.source_context == source_context:
                return sdwan

        sdwan = FGSDWan(source_context=source_context)
        self.config.sdwans.append(sdwan)
        return sdwan

    def consume(self, expected_type: TokenType) -> Token:
        token = self.next_token()

        if not token:
            raise ParserError(
                f"Expected {expected_type}, but reached end of file"
            )

        if token.type != expected_type:
            raise ParserError(
                f"Expected {expected_type} at line "
                f"{token.line_number}, got {token.type} ({token.value})"
            )

        return token

    def parse(self) -> FGConfig:
        while self.peek():
            token = self.next_token()

            if token.type == TokenType.COMMENT:
                self._parse_header_comment(token.value)
                continue

            elif token.type == TokenType.CONFIG:
                self.parse_config_block("")

            else:
                pass

        return self.config

    def _parse_header_comment(self, value: str) -> None:
        """Extract recognized FortiOS header metadata without changing comments."""
        config_version = re.match(
            r"^#\s*config-version\s*=\s*(.+)$",
            value,
            flags=re.IGNORECASE,
        )
        if config_version:
            header = config_version.group(1)
            version = re.search(r"(?:^|-)(\d+\.\d+\.\d+)(?:-|:|$)", header)
            build = re.search(r"(?:^|-)build(\d+)(?:-|:|$)", header, re.IGNORECASE)
            if version:
                self.config.source_version = version.group(1)
            if build:
                self.config.source_build = build.group(1)
            return

        build_number = re.match(
            r"^#\s*buildno\s*=\s*(\d+)",
            value,
            flags=re.IGNORECASE,
        )
        if build_number and not self.config.source_build:
            self.config.source_build = build_number.group(1)

    def parse_config_block(self, parent_path: str):
        current_path = self.read_section_name()

        if not current_path:
            return

        full_path = f"{parent_path} {current_path}".strip()
        self.parse_config_contents(full_path)

    def read_section_name(self) -> str:
        section_parts = []

        while self.peek() and self.peek().type == TokenType.STRING:
            section_parts.append(self.next_token().value)

        return " ".join(section_parts)

    def parse_config_contents(self, full_path: str):
        if full_path == "vdom":
            self._parse_vdom_contents()
            return

        if full_path in (
            STRUCTURED_SECURITY_SECTIONS
            | STRUCTURED_ROUTING_SECTIONS
            | STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
            | STRUCTURED_IDENTITY_SECTIONS
            | STRUCTURED_OPERATIONAL_SECTIONS
        ):
            self._parse_structured_source_section(full_path)
            return

        # Keep an unknown migration-relevant block as a recursive source tree
        # instead of routing its edits through ``build_model`` and losing them.
        # The explicit set below covers paths that are handled by the existing
        # edit/global parser but are not part of CONTEXTUAL_MODEL_SECTIONS.
        known_edit_or_global_sections = {
            "system settings", "system global", "system dns",
            "system session-ttl", "system session-ttl port",
            "system sdwan", "system sdwan zone", "system sdwan members",
            "system sdwan health-check", "system sdwan service",
            "system sdwan duplication", "system sdwan neighbor",
            "vpn ssl settings", "vpn ssl settings authentication-rule",
            "user setting", "user quarantine", "web-proxy global",
            "firewall internet-service-name",
            "firewall internet-service-definition",
            "vpn certificate remote", "vpn certificate local", "vpn certificate ca",
            "firewall ssh local-key", "firewall ssh local-ca",
            "system session-helper",
            "endpoint-control fctems", "user ldap", "user fsso", "user adgrp",
            "user saml", "user local", "user group", "system admin",
            "system accprofile", "user fortitoken", "vpn ssl web portal",
            "vpn ssl web host-check-software", "firewall sniffer",
            "authentication scheme", "authentication rule",
        }
        known_source_paths = (
            CONTEXTUAL_MODEL_SECTIONS
            | known_edit_or_global_sections
            | STRUCTURED_SECURITY_SECTIONS
            | STRUCTURED_ROUTING_SECTIONS
            | STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
            | STRUCTURED_IDENTITY_SECTIONS
            | STRUCTURED_OPERATIONAL_SECTIONS
        )
        if full_path not in known_source_paths:
            self._parse_unknown_source_section(full_path)
            return

        source_commands: List[SourceCommand] = []
        while self.peek():
            token = self.peek()

            if token.type == TokenType.END:
                self.consume(TokenType.END)
                break

            elif token.type == TokenType.EDIT:
                self.parse_edit_block(full_path)

            elif token.type == TokenType.SET:
                key, values = self.parse_set()
                source_commands.append(
                    self._source_command("set", key, values)
                )
                self.apply_global_set(full_path, key, values)

            elif token.type == TokenType.UNSET:
                key, values = self.parse_key_values(TokenType.UNSET)
                source_commands.append(
                    self._source_command("unset", key, values)
                )
                self.apply_global_unset(full_path, key)

            elif token.type == TokenType.APPEND:
                key, values = self.parse_key_values(TokenType.APPEND)
                source_commands.append(
                    self._source_command("append", key, values)
                )

            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)
                nested_name = self.read_section_name()
                nested_path = f"{full_path} {nested_name}".strip()
                if full_path == "vpn ssl settings" and nested_name == "authentication-rule":
                    raw_rules = self.parse_nested_edit_collection(nested_path)
                    self._attach_ssl_vpn_authentication_rules(raw_rules)
                else:
                    self.parse_config_contents(nested_path)

            else:
                self.next_token()

        if source_commands:
            self.source_inventory_items.append(
                SourceInventoryItem(
                    domain=full_path.split(" ", 1)[0] if full_path else "unknown",
                    source_path=full_path,
                    source_context=self.current_context,
                    commands=source_commands,
                )
            )

    def _parse_unknown_source_section(self, source_path: str) -> None:
        """Capture an unregistered config block without interpreting it."""
        root = self.parse_source_node("config", source_path)
        structured = FGStructuredSourceObject(
            source_path=source_path,
            source_context=self.current_context or "root",
            root=root,
        )
        self.structured_source_objects.append(structured)
        self.config.structured_source_objects.append(structured)

        # Existing source inventory consumers expect edited objects at the
        # top level.  Retain that shape while the structured source object
        # above preserves the complete config/edit hierarchy.
        edit_children = [child for child in root.children if child.node_type == "edit"]
        if edit_children:
            for child in edit_children:
                inventory = self._source_node_inventory(child, source_path, child.name)
                inventory.notes.append("unknown-section-source-fallback")
                self.source_inventory_items.append(inventory)
        elif root.commands or root.children:
            inventory = self._source_node_inventory(root, source_path)
            inventory.notes.append("unknown-section-source-fallback")
            self.source_inventory_items.append(inventory)

    def _parse_vdom_contents(self) -> None:
        """Remove the VDOM wrapper while retaining its execution context."""
        previous_context = self.current_context
        while self.peek():
            token = self.peek()
            if token.type == TokenType.END:
                self.consume(TokenType.END)
                break
            if token.type != TokenType.EDIT:
                self.next_token()
                continue
            self.consume(TokenType.EDIT)
            self.current_context = self.consume(TokenType.STRING).value
            self._execution_context(self.current_context)
            while self.peek():
                token = self.peek()
                if token.type == TokenType.NEXT:
                    self.consume(TokenType.NEXT)
                    break
                if token.type == TokenType.CONFIG:
                    self.consume(TokenType.CONFIG)
                    self.parse_config_contents(self.read_section_name())
                else:
                    self.next_token()
        self.current_context = previous_context

    def _execution_context(self, vdom: Optional[str] = None) -> FGExecutionContext:
        context_name = vdom or self.current_context or "root"
        for context in self.config.execution_contexts:
            if context.vdom == context_name:
                return context
        context = FGExecutionContext(vdom=context_name)
        self.config.execution_contexts.append(context)
        return context

    def _parse_structured_source_section(self, source_path: str) -> None:
        root = self.parse_source_node("config", source_path)
        top_edits = [child for child in root.children if child.node_type == "edit"]
        current_ctx = self.current_context or "root"
        objects = [
            FGStructuredSourceObject(
                source_path=source_path,
                name=child.name,
                source_id=child.name if child.name.isdigit() else None,
                source_context=current_ctx,
                root=child,
            )
            for child in top_edits
        ]
        if root.commands or any(child.node_type != "edit" for child in root.children):
            objects.append(FGStructuredSourceObject(source_path=source_path, source_context=current_ctx, root=root))
        if not objects:
            objects.append(FGStructuredSourceObject(source_path=source_path, source_context=current_ctx, root=root))

        for source_object in objects:
            self.structured_source_objects.append(source_object)
            self.config.structured_source_objects.append(source_object)
            inventory = self._source_node_inventory(
                source_object.root,
                source_path,
                source_object.name,
            )
            if source_path in STRUCTURED_ROUTING_SECTIONS:
                note = "structured-routing-protocol"
            elif source_path in STRUCTURED_ROUTING_DEPENDENCY_SECTIONS:
                note = "structured-routing-dependency"
            elif source_path in STRUCTURED_IDENTITY_SECTIONS:
                note = "structured-identity-routing"
            elif source_path in STRUCTURED_OPERATIONAL_SECTIONS:
                note = "structured-operational-config"
            else:
                note = "structured-security-profile"
            inventory.notes.append(note)
            self.source_inventory_items.append(inventory)

        self._build_structured_typed_parents(source_path, top_edits)

    def _build_structured_typed_parents(
        self,
        source_path: str,
        top_edits: List[FGSourceNode],
    ) -> None:
        """Expose common fields while keeping the recursive source tree authoritative."""
        models: Dict[str, tuple[str, Any]] = {
            "firewall network-service-dynamic": ("network_service_dynamics", FGNetworkServiceDynamic),
            "system sdn-connector": ("sdn_connectors", FGSDNConnector),
            "user radius": ("radius_servers", FGUserRADIUS),
            "user fsso-polling": ("fsso_polling", FGFSSOPolling),
            "firewall profile-group": ("profile_groups", FGProfileGroup),
            "user tacacs+": ("tacacs_servers", FGUserTACACS),
            "system link-monitor": ("link_monitors", FGLinkMonitor),
            "system switch-interface": ("topology_objects", FGTopologyObject),
            "system virtual-wire-pair": ("topology_objects", FGTopologyObject),
            "system vdom-link": ("topology_objects", FGTopologyObject),
            "system pppoe-interface": ("topology_objects", FGTopologyObject),
            "firewall access-proxy": ("access_proxies", FGAccessProxy),
            "firewall access-proxy6": ("access_proxies", FGAccessProxy),
            "firewall access-proxy-virtual-host": ("access_proxies", FGAccessProxy),
            "firewall access-proxy-ssh-client-cert": ("access_proxies", FGAccessProxy),
            "endpoint-control fctems-override": ("ems_overrides", FGEMSOverride),
            "vpn ssl web realm": ("ssl_vpn_realms", FGSSLVPNRealm),
            "vpn ssl web user-bookmark": ("ssl_vpn_bookmarks", FGSSLVPNBookmark),
            "vpn ssl web group-bookmark": ("ssl_vpn_bookmarks", FGSSLVPNBookmark),
            "vpn ipsec manualkey-interface": ("manualkey_interfaces", FGManualKeyInterface),
        }
        target = models.get(source_path)
        if target is None:
            return
        collection_name, model = target
        list_fields = {
            "srcintf", "members", "member", "virtual_hosts", "realservers",
            "capabilities", "groups", "users",
        }
        if source_path == "system link-monitor":
            list_fields.add("server")
        secret_fields = {
            "password", "passwd", "secret", "psksecret", "token", "key", "key2", "key3",
            "api_key", "key_string", "private_key", "encryption_key",
            "authentication_key", "auth_key", "secondary_key", "tertiary_key",
        }
        for node in top_edits:
            attributes: Dict[str, Any] = {
                "name": node.name,
                "source_context": self.current_context or "root",
            }
            for command in node.commands:
                key = command.key.replace("-", "_")
                if key in secret_fields:
                    if key in {
                        "secret", "password", "passwd", "token", "key", "key2", "key3", "api_key",
                        "key_string", "shared_secret", "secondary_key", "tertiary_key",
                    }:
                        attributes["has_password" if source_path == "user fsso-polling" else "has_secret"] = True
                    elif key == "encryption_key":
                        attributes["has_encryption_key"] = True
                    elif key in {"authentication_key", "auth_key"}:
                        attributes["has_authentication_key"] = True
                    continue
                values = list(command.values)
                if key in list_fields:
                    attributes[key] = values
                elif not values:
                    attributes[key] = True
                elif len(values) == 1:
                    attributes[key] = values[0]
                else:
                    attributes[key] = " ".join(values)
            if source_path.endswith("6"):
                attributes["family"] = "ipv6"
                attributes["address_family"] = "ipv6"
            if source_path == "vpn ssl web user-bookmark":
                attributes["bookmark_type"] = "user"
            elif source_path == "vpn ssl web group-bookmark":
                attributes["bookmark_type"] = "group"
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(model.model_fields),
            )
            if source_path == "user radius":
                accounting_servers = []
                for child in node.children:
                    if child.node_type != "config" or child.name != "accounting-server":
                        continue
                    for entry in child.children:
                        if entry.node_type != "edit":
                            continue
                        child_attributes: Dict[str, Any] = {"id": entry.name}
                        for command in entry.commands:
                            key = command.key.replace("-", "_")
                            values = list(command.values)
                            if key in secret_fields:
                                if key in {"secret", "password", "passwd"}:
                                    child_attributes["has_secret"] = True
                                continue
                            if not values:
                                child_attributes[key] = True
                            elif len(values) == 1:
                                child_attributes[key] = values[0]
                            else:
                                child_attributes[key] = " ".join(values)
                        child_attributes["extra_settings"] = _extract_extra_settings(
                            child_attributes,
                            set(FGUserRADIUSAccountingServer.model_fields),
                        )
                        accounting_servers.append(FGUserRADIUSAccountingServer(**child_attributes))
                attributes["accounting_servers"] = accounting_servers
            elif source_path == "user fsso-polling":
                attributes["ad_groups"] = [
                    FGFSSOPollingADGroup(
                        name=entry.name,
                        extra_settings=_extract_extra_settings(
                            {command.key.replace("-", "_"): command.values for command in entry.commands},
                            set(FGFSSOPollingADGroup.model_fields),
                        ),
                    )
                    for child in node.children
                    if child.node_type == "config" and child.name == "adgrp"
                    for entry in child.children
                    if entry.node_type == "edit"
                ]
            getattr(self.config, collection_name).append(model(**attributes))

    def parse_source_node(self, node_type: str, node_name: str) -> FGSourceNode:
        node = FGSourceNode(node_type=node_type, name=node_name)
        while self.peek():
            token = self.peek()
            if token.type == TokenType.END and node_type == "config":
                self.consume(TokenType.END)
                break
            if token.type == TokenType.NEXT and node_type == "edit":
                self.consume(TokenType.NEXT)
                break
            if token.type == TokenType.EDIT:
                self.consume(TokenType.EDIT)
                name = self.consume(TokenType.STRING).value
                node.children.append(self.parse_source_node("edit", name))
            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)
                name = self.read_section_name()
                node.children.append(self.parse_source_node("config", name))
            elif token.type in {TokenType.SET, TokenType.UNSET, TokenType.APPEND}:
                operation = token.type.value
                key, values = self.parse_key_values(token.type)
                safe = self._source_command(operation, key, values)
                node.commands.append(
                    FGSourceCommand(
                        operation=safe.operation,
                        key=safe.key,
                        values=safe.values,
                    )
                )
            else:
                self.next_token()
        return node

    def _source_node_inventory(
        self,
        node: FGSourceNode,
        source_path: str,
        object_name: Optional[str] = None,
    ) -> SourceInventoryItem:
        return SourceInventoryItem(
            domain=source_path.split(" ", 1)[0],
            source_path=source_path,
            source_context=self.current_context,
            name=object_name if object_name is not None else node.name,
            source_id=(
                object_name
                if object_name is not None and object_name.isdigit()
                else None
            ),
            commands=[
                SourceCommand(
                    operation=command.operation,
                    key=command.key,
                    values=list(command.values),
                )
                for command in node.commands
            ],
            children=[
                self._source_node_inventory(
                    child,
                    f"{source_path} {child.name}" if child.node_type == "config" else source_path,
                    child.name,
                )
                for child in node.children
            ],
            notes=[f"source-node:{node.node_type}"],
        )

    def parse_edit_block(self, section_path: str):
        attributes = self.parse_edit_attributes(section_path)
        self.build_model(section_path, attributes)

    def parse_edit_attributes(
        self,
        section_path: str,
    ) -> Dict[str, Any]:
        self.consume(TokenType.EDIT)

        name_token = self.consume(TokenType.STRING)
        item_name = name_token.value

        attributes = {
            "name": item_name,
        }
        source_commands: List[SourceCommand] = []

        if item_name.isdigit():
            attributes["id"] = int(item_name)
            if section_path == "firewall policy":
                attributes.pop("name", None)

        while self.peek():
            token = self.peek()

            if token.type in (
                TokenType.NEXT,
                TokenType.END,
            ):
                if token.type == TokenType.NEXT:
                    self.consume(TokenType.NEXT)

                break

            elif token.type == TokenType.SET:
                key, values = self.parse_set()
                safe_values = (
                    ["[REDACTED]"]
                    if section_path.endswith(" form-data") and key == "value"
                    else values
                )

                source_commands.append(
                    self._source_command("set", key, safe_values)
                )

                self.apply_attribute(
                    attributes,
                    key,
                    values,
                    section_path,
                )

            elif token.type == TokenType.UNSET:
                key, values = self.parse_key_values(TokenType.UNSET)
                clean_key = self._normalize_attribute_key(key)
                attributes.pop(clean_key, None)
                if section_path in SECTION_EXPLICIT_FIELDS:
                    attributes.get("source_explicit_fields", set()).discard(
                        clean_key
                    )
                attributes.setdefault("source_unset_settings", []).append(key)
                source_commands.append(
                    self._source_command("unset", key, values)
                )

            elif token.type == TokenType.APPEND:
                key, values = self.parse_key_values(TokenType.APPEND)
                self.apply_append_attribute(
                    attributes,
                    key,
                    values,
                    section_path,
                )
                source_commands.append(
                    self._source_command("append", key, values)
                )

            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)

                nested_name = self.read_section_name()
                nested_path = (
                    f"{section_path} {nested_name}".strip()
                )

                if (
                    section_path == "system interface"
                    and nested_name == "secondaryip"
                ):
                    attributes["secondary_ips"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path in {"firewall vip", "firewall vip6"}
                    and nested_name == "realservers"
                ):
                    attributes["realservers"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path in {"firewall addrgrp", "firewall addrgrp6"}
                    and nested_name == "tagging"
                ):
                    attributes["tagging"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "firewall address" and nested_name == "list":
                    attributes["address_list"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path in {
                        "firewall address",
                        "firewall address6",
                        "firewall multicast-address",
                        "firewall multicast-address6",
                    }
                    and nested_name == "tagging"
                ):
                    attributes["tagging"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "system dhcp server"
                    and nested_name == "ip-range"
                ):
                    attributes["ip_ranges"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path == "system dhcp server"
                    and nested_name == "exclude-range"
                ):
                    attributes["exclude_ranges"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path == "system dhcp server"
                    and nested_name == "reserved-address"
                ):
                    attributes["reserved_addresses"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path == "system dhcp server"
                    and nested_name == "options"
                ):
                    attributes["options"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif (
                    section_path == "ips sensor"
                    and nested_name == "entries"
                ):
                    attributes["entries"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
                    )

                elif section_path == "ips sensor entries" and nested_name == "exempt-ip":
                    attributes["exempt_ips"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "firewall internet-service-definition"
                    and nested_name == "entry"
                ):
                    attributes["entries"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "firewall internet-service-definition entry"
                    and nested_name == "port-range"
                ):
                    attributes["port_ranges"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "system sdwan health-check"
                    and nested_name == "sla"
                ):
                    attributes["sla"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "system sdwan service"
                    and nested_name == "sla"
                ):
                    attributes["sla"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif section_path == "user group" and nested_name == "match":
                    attributes["match"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif section_path == "user group" and nested_name == "guest":
                    attributes["guests"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "vpn ssl web portal"
                    and nested_name == "host-check-software"
                ):
                    attributes["host_checks"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif section_path == "vpn ssl web portal" and nested_name == "bookmark-group":
                    attributes["bookmark_groups"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal" and nested_name == "landing-page":
                    attributes["landing_pages"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal" and nested_name == "mac-addr-check-rule":
                    attributes["mac_address_check_rules"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal" and nested_name == "os-check-list":
                    attributes["os_check_list"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal" and nested_name == "split-dns":
                    attributes["split_dns"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal bookmark-group" and nested_name == "bookmarks":
                    attributes["bookmarks"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal bookmark-group bookmarks" and nested_name == "form-data":
                    attributes["form_data"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "vpn ssl web portal landing-page" and nested_name == "form-data":
                    attributes["form_data"] = self.parse_nested_edit_collection(nested_path)

                elif (
                    section_path == "vpn ssl web host-check-software"
                    and nested_name == "check-item-list"
                ):
                    attributes["check_items"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "firewall DoS-policy"
                    and nested_name == "anomaly"
                ):
                    attributes["anomalies"] = self.parse_nested_edit_collection(
                        nested_path
                    )

                elif (
                    section_path == "system accprofile"
                    and nested_name in {
                        "fwgrp-permission", "loggrp-permission",
                        "netgrp-permission", "sysgrp-permission",
                        "utmgrp-permission",
                    }
                ):
                    attributes.setdefault("permission_blocks", []).append(
                        self._parse_admin_profile_permission_block(nested_name)
                    )

                elif nested_name:
                    nested_node = self.parse_source_node("config", nested_name)
                    if section_path == "system interface" and nested_name == "ipv6":
                        ipv6_source_settings = {}
                        for command in nested_node.commands:
                            if command.operation != "set":
                                continue

                            clean_key = command.key.replace("-", "_")
                            attribute_key = "ipv6_autoconf" if clean_key == "autoconf" else clean_key
                            source_value = (
                                command.values[0]
                                if len(command.values) == 1
                                else list(command.values)
                            )
                            ipv6_source_settings[clean_key] = source_value

                            if clean_key in FG_INTERFACE_IPV6_LIST_FIELDS:
                                attributes[attribute_key] = list(command.values)
                            elif clean_key in FG_INTERFACE_IPV6_SCALAR_FIELDS:
                                # Keep malformed/multi-token values visible as
                                # source text; the transformer validates them.
                                attributes[attribute_key] = (
                                    command.values[0]
                                    if len(command.values) == 1
                                    else " ".join(command.values)
                                )

                        extra_node = next(
                            (child for child in nested_node.children if child.name == "ip6-extra-addr"),
                            None,
                        )
                        if extra_node is not None:
                            attributes["ipv6_extra_addresses"] = [
                                FGInterfaceIPv6ExtraAddress(
                                    source_address=entry.name,
                                    extra_settings=_extract_extra_settings(
                                        {
                                            command.key.replace("-", "_"): (
                                                command.values[0]
                                                if len(command.values) == 1
                                                else list(command.values)
                                            )
                                            for command in entry.commands
                                        },
                                        {"source_address", "extra_settings"},
                                    ),
                                )
                                for entry in extra_node.children
                                if entry.node_type == "edit"
                            ]
                        def ipv6_entry_values(entry, list_fields=()):
                            values = {}
                            for command in entry.commands:
                                key = command.key.replace("-", "_")
                                values[key] = (
                                    list(command.values)
                                    if len(command.values) > 1
                                    else (command.values[0] if command.values else True)
                                )
                                if key in list_fields and not isinstance(values[key], list):
                                    values[key] = [values[key]]
                            return values

                        def safe_int(values, key):
                            value = values.get(key)
                            try:
                                values[key] = int(value) if value is not None else None
                            except (TypeError, ValueError):
                                values.pop(key, None)
                                values.setdefault("extra_settings", {})[f"unparsed_{key}"] = value

                        prefix_node = next((child for child in nested_node.children if child.name == "ip6-prefix-list"), None)
                        if prefix_node is not None:
                            attributes["ipv6_prefix_advertisements"] = []
                            for entry in prefix_node.children:
                                values = ipv6_entry_values(entry, {"dnssl", "rdnss"})
                                values["prefix"] = entry.name
                                for key in ("preferred_life_time", "valid_life_time"):
                                    safe_int(values, key)
                                values["extra_settings"] = sanitize_source_attributes(values.pop("extra_settings", {}))
                                attributes["ipv6_prefix_advertisements"].append(FGIPv6PrefixAdvertisement(**values))

                        delegated_node = next((child for child in nested_node.children if child.name == "ip6-delegated-prefix-list"), None)
                        if delegated_node is not None:
                            attributes["ipv6_delegated_prefix_advertisements"] = []
                            for entry in delegated_node.children:
                                values = ipv6_entry_values(entry, {"rdnss"})
                                values["prefix_id"] = entry.name
                                safe_int(values, "delegated_prefix_iaid")
                                values["extra_settings"] = sanitize_source_attributes(values.pop("extra_settings", {}))
                                attributes["ipv6_delegated_prefix_advertisements"].append(FGIPv6DelegatedPrefixAdvertisement(**values))

                        iapd_node = next((child for child in nested_node.children if child.name == "dhcp6-iapd-list"), None)
                        if iapd_node is not None:
                            attributes["dhcp6_iapd"] = []
                            for entry in iapd_node.children:
                                values = ipv6_entry_values(entry)
                                values["source_iaid"] = entry.name
                                try:
                                    values["iaid"] = int(entry.name)
                                except (TypeError, ValueError):
                                    values["iaid"] = None
                                    values.setdefault("extra_settings", {})["unparsed_iaid"] = entry.name
                                for key in ("prefix_hint_plt", "prefix_hint_vlt"):
                                    safe_int(values, key)
                                values["extra_settings"] = sanitize_source_attributes(values.pop("extra_settings", {}))
                                attributes["dhcp6_iapd"].append(FGDHCPv6IAPD(**values))
                        vrrp_node = next((child for child in nested_node.children if child.name == "vrrp6"), None)
                        if vrrp_node is not None:
                            attributes["vrrp6"] = []
                            for entry in vrrp_node.children:
                                values = ipv6_entry_values(entry)
                                values["source_vrid"] = entry.name
                                try:
                                    values["vrid"] = int(entry.name)
                                except (TypeError, ValueError):
                                    values["vrid"] = None
                                    values.setdefault("extra_settings", {})["unparsed_vrid"] = entry.name
                                for key in ("adv_interval", "priority", "vrgrp"):
                                    safe_int(values, key)
                                values["extra_settings"] = sanitize_source_attributes(values.pop("extra_settings", {}))
                                attributes["vrrp6"].append(FGInterfaceVRRP6(**values))
                        attributes["ipv6_source_settings"] = sanitize_source_attributes(
                            ipv6_source_settings
                        )
                    attributes.setdefault("nested_configs", []).append(nested_node)
                    inventory = self._source_node_inventory(
                        nested_node, nested_path, item_name
                    )
                    inventory.notes.append(
                        "interface-nested-config"
                        if section_path == "system interface"
                        else "nested-source-config"
                    )
                    self.source_inventory_items.append(inventory)

            else:
                self.next_token()

        inventory_name = item_name
        if section_path == "firewall policy":
            inventory_name = attributes.get("name")

        self.source_inventory_items.append(
            SourceInventoryItem(
                domain=section_path.split(" ", 1)[0] if section_path else "unknown",
                source_path=section_path,
                name=inventory_name,
                source_id=item_name if item_name.isdigit() else None,
                source_context=self.current_context,
                commands=source_commands,
            )
        )
        return attributes

    def _parse_admin_profile_permission_block(self, name: str) -> Dict[str, Any]:
        """Parse a direct-setting accprofile child while retaining unknown keys."""
        settings: Dict[str, Any] = {}
        while self.peek():
            token = self.peek()
            if token.type == TokenType.END:
                self.consume(TokenType.END)
                break
            if token.type == TokenType.SET:
                key, values = self.parse_set()
                self.apply_attribute(settings, key, values)
            elif token.type == TokenType.UNSET:
                key, _ = self.parse_key_values(TokenType.UNSET)
                settings.pop(self._normalize_attribute_key(key), None)
            else:
                self.next_token()
        return {"name": name, "settings": settings}

    def parse_nested_edit_collection(
        self,
        section_path: str,
    ) -> List[Dict[str, Any]]:
        items = []

        while self.peek():
            token = self.peek()

            if token.type == TokenType.END:
                self.consume(TokenType.END)
                break

            if token.type == TokenType.EDIT:
                items.append(
                    self.parse_edit_attributes(
                        section_path
                    )
                )

            else:
                self.next_token()

        return items

    def _attach_ssl_vpn_authentication_rules(
        self,
        raw_rules: List[Dict[str, Any]],
    ) -> None:
        if not self.config.ssl_vpn_settings:
            self.config.ssl_vpn_settings = FGSSLVPNSettings()
        rules = []
        for attributes in raw_rules:
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSSLVPNAuthenticationRule.model_fields),
            )
            rules.append(FGSSLVPNAuthenticationRule(**attributes))
        self.config.ssl_vpn_settings.authentication_rules.extend(rules)

    @staticmethod
    def _normalize_int_list(attributes: Dict[str, Any], key: str) -> None:
        values = attributes.get(key, [])
        normalized = []
        unparsed = []
        for value in values:
            try:
                normalized.append(int(value))
            except (TypeError, ValueError):
                unparsed.append(value)
        attributes[key] = normalized
        if unparsed:
            attributes[f"unparsed_{key}"] = unparsed

    @staticmethod
    def _normalize_optional_int(attributes: Dict[str, Any], key: str) -> None:
        value = attributes.get(key)
        if value is None:
            return
        try:
            attributes[key] = int(value)
        except (TypeError, ValueError):
            attributes.pop(key, None)
            attributes[f"unparsed_{key}"] = value

    def parse_key_values(
        self,
        command_type: TokenType,
    ) -> tuple[str, List[str]]:
        self.consume(command_type)

        key_token = self.consume(TokenType.STRING)
        key = key_token.value

        values = []
        current_line = key_token.line_number

        while (
            self.peek()
            and self.peek().type == TokenType.STRING
            and self.peek().line_number == current_line
        ):
            values.append(
                self.next_token().value
            )

        return key, values

    def parse_set(self) -> tuple[str, List[str]]:
        return self.parse_key_values(TokenType.SET)

    @staticmethod
    def _source_command(
        operation: str,
        key: str,
        values: List[str],
    ) -> SourceCommand:
        sanitized = sanitize_source_attributes({key: values})
        sanitized_value = sanitized.get(key.replace("-", "_"), values)
        safe_values = (
            [sanitized_value]
            if isinstance(sanitized_value, str)
            else list(sanitized_value)
        )
        return SourceCommand(
            operation=operation,
            key=key,
            values=safe_values,
        )

    @staticmethod
    def _normalize_attribute_key(key: str) -> str:
        clean_key = key.replace("-", "_")
        if clean_key.lower() == "secondary_ip":
            return "secondary_ip"
        return clean_key

    @staticmethod
    def _record_explicit_field(
        attributes: Dict[str, Any],
        section_path: str,
        key: str,
    ) -> None:
        clean_key = key.replace("-", "_")
        if clean_key not in SECTION_EXPLICIT_FIELDS.get(section_path, set()):
            return
        attributes.setdefault("source_explicit_fields", set()).add(clean_key)

    def apply_append_attribute(
        self,
        attributes: Dict[str, Any],
        key: str,
        values: List[str],
        section_path: str = "",
    ) -> None:
        self._record_explicit_field(attributes, section_path, key)
        clean_key = self._normalize_attribute_key(key)
        if clean_key not in attributes:
            self.apply_attribute(attributes, key, values, section_path)
            return

        current = attributes[clean_key]
        if isinstance(current, list):
            current.extend(values)
        elif values:
            attributes[clean_key] = " ".join([str(current), *values])

    def apply_attribute(
        self,
        attributes: Dict[str, Any],
        key: str,
        values: List[str],
        section_path: str = "",
    ):
        self._record_explicit_field(attributes, section_path, key)
        clean_key = self._normalize_attribute_key(key)
        if clean_key == "tacacs+_server":
            clean_key = "tacacs_server"
        if clean_key in {"password", "passwd", "ppk_secret"} and section_path == "user group guest":
            attributes["has_password"] = bool(values)
            return

        if section_path in {
            "vpn certificate remote",
            "vpn certificate local",
            "vpn certificate ca",
        }:
            self._apply_certificate_attribute(
                attributes,
                clean_key,
                values,
            )
            return

        if section_path in {
            "firewall ssh local-key",
            "firewall ssh local-ca",
        }:
            self._apply_ssh_key_attribute(attributes, clean_key, values)
            return

        if section_path == "vpn ipsec phase1-interface" and clean_key == "psksecret":
            attributes["has_psk"] = bool(values)
            return

        if section_path == "system interface" and clean_key == "password":
            has_password, password_format = _classify_pppoe_password(values)
            attributes["has_pppoe_password"] = has_password
            attributes["pppoe_password_format"] = password_format
            attributes["password"] = " ".join(str(item) for item in values)
            return

        if section_path == "system admin" and clean_key in ADMIN_SECRET_FIELDS:
            attributes["credential_configured"] = bool(values)
            return

        if section_path == "user fortitoken" and clean_key in ADMIN_SECRET_FIELDS:
            return

        if section_path in IDENTITY_SECTIONS and clean_key in IDENTITY_SECRET_FIELDS:
            if clean_key == "ppk_secret":
                attributes["has_ppk_secret"] = True
            elif clean_key.startswith("password") or clean_key == "passwd":
                attributes["has_password"] = True
                if clean_key != "password":
                    attributes[f"has_{clean_key}"] = True
            return

        if (
            section_path in {"router static", "router static6"}
            and clean_key == "dstaddr"
        ):
            attributes[clean_key] = (
                values[0] if len(values) == 1 else " ".join(values)
            )
            return

        list_fields = {
            "allowaccess",
            "member",
            "day",
            "srcintf",
            "dstintf",
            "srcaddr",
            "dstaddr",
            "groups",
            "users",
            "service",
            "poolname",
            "proposal",
            "internet_service_name",
            "exclude_ip",
            "mappedip",
            "extaddr",
            "src_filter",
            "srcintf_filter",
            "monitor",
            "ztna_ems_tag",
            "ztna_ems_tag_secondary",
            "ztna_geo_tag",
            "capabilities",
        }

        if (
            clean_key in list_fields
            or clean_key in SECTION_LIST_FIELDS.get(
                section_path,
                set(),
            )
            or (
                clean_key == "interface"
                and section_path == "system zone"
            )
        ):
            attributes[clean_key] = values

        elif len(values) == 0:
            attributes[clean_key] = True

        elif len(values) == 1:
            attributes[clean_key] = values[0]

        else:
            if key == "subnet" or key == "ip":
                attributes[clean_key] = (
                    f"{values[0]} {values[1]}"
                )

            elif key in [
                "tcp-portrange",
                "udp-portrange",
                "sctp-portrange",
            ]:
                attributes[clean_key] = ",".join(
                    values
                )

            else:
                attributes[clean_key] = " ".join(
                    values
                )

    @staticmethod
    def _apply_certificate_attribute(
        attributes: Dict[str, Any],
        clean_key: str,
        values: List[str],
    ) -> None:
        """Retain safe certificate fields and discard secret values."""
        normalized_key = clean_key.lower()
        value = values[0] if len(values) == 1 else " ".join(values)

        if normalized_key == "private_key":
            attributes["has_private_key"] = True
            attributes["private_key_encrypted"] = any(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----" in item
                for item in values
            )
            return

        if normalized_key in {"password", "passwd"} or any(
            marker in normalized_key
            for marker in (
                "password",
                "passwd",
                "passphrase",
                "credential",
                "secret",
                "token",
                "community",
                "auth_key",
                "api_key",
                "private_key",
            )
        ) or normalized_key == "key":
            if "password" in normalized_key or "passwd" in normalized_key:
                attributes["has_password"] = True
            return

        if normalized_key in {"certificate", "remote", "ca"}:
            attributes["public_certificate"] = value
            attributes["has_certificate"] = bool(value)
            return

        if normalized_key == "comment":
            normalized_key = "comments"

        attributes[normalized_key] = value if values else True

    @staticmethod
    def _apply_ssh_key_attribute(
        attributes: Dict[str, Any],
        clean_key: str,
        values: List[str],
    ) -> None:
        """Retain public SSH metadata while discarding credentials immediately."""
        normalized_key = clean_key.lower()
        value = values[0] if len(values) == 1 else " ".join(values)

        if normalized_key == "private_key":
            attributes["has_private_key"] = bool(values)
            return
        if normalized_key in {"password", "passwd"}:
            attributes["has_password"] = bool(values)
            return
        if normalized_key in {"public_key", "source"}:
            attributes[normalized_key] = value
            return

        attributes[normalized_key] = value if values else True

    def apply_global_set(
        self,
        section_path: str,
        key: str,
        values: List[str],
    ):
        if section_path == "system settings":
            context = self._execution_context()
            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"central_nat", "ngfw_mode", "opmode"}:
                setattr(context, clean_key, value)
            else:
                context.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system session-ttl":
            if not self.config.session_ttl_settings:
                self.config.session_ttl_settings = FGSessionTTLSettings()
            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key == "default" and values:
                try:
                    self.config.session_ttl_settings.default_timeout = int(values[0])
                except ValueError:
                    self.config.session_ttl_settings.extra_settings["unparsed_default"] = value
            else:
                self.config.session_ttl_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system global":
            if not self.config.system_global:
                self.config.system_global = (
                    FGSystemGlobal(
                        hostname=None
                    )
                )

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)

            if clean_key == "hostname" and values:
                self.config.system_global.hostname = (
                    values[0]
                )

            elif clean_key == "admin_sport" and values:
                self.config.system_global.admin_sport = (
                    int(values[0])
                )

            elif clean_key == "timezone" and values:
                self.config.system_global.timezone = values[0]

            elif clean_key == "opmode" and values:
                self._execution_context().opmode = values[0]

            elif clean_key != "extra_settings":
                self.config.system_global.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system dns":
            if not self.config.dns:
                self.config.dns = FGDns()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {
                "primary", "secondary", "protocol", "server_select_method",
                "domain", "interface_select_method", "interface", "source_ip",
                "source_ip6", "ssl_certificate",
            } and values:
                setattr(self.config.dns, clean_key, values[0] if len(values) == 1 else " ".join(values))
                if clean_key not in {"primary", "secondary"}:
                    self.config.dns.extra_settings.update(
                        sanitize_source_attributes({clean_key: value})
                    )
            elif clean_key in {"timeout", "retry"} and values:
                try:
                    setattr(self.config.dns, clean_key, int(values[0]))
                    self.config.dns.extra_settings[clean_key] = int(values[0])
                except (TypeError, ValueError):
                    self.config.dns.extra_settings[clean_key] = value
            elif clean_key != "extra_settings":
                self.config.dns.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system sdwan":
            sdwan = self._sdwan_for_current_context()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"status", "load_balance_mode"} and values:
                setattr(sdwan, clean_key, value)
            elif clean_key != "extra_settings":
                sdwan.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "vpn ssl settings":
            if not self.config.ssl_vpn_settings:
                self.config.ssl_vpn_settings = FGSSLVPNSettings()
            clean_key = key.replace("-", "_")
            if clean_key == "servercert":
                self.config.ssl_vpn_settings.servercert_configured = True
            if clean_key in SECTION_LIST_FIELDS["vpn ssl settings"]:
                value: Any = list(values)
            elif clean_key in {
                "login_attempt_limit", "login_block_time", "auth_timeout",
                "idle_timeout", "port", "deflate_compression_level",
                "deflate_min_data_size", "dtls_heartbeat_fail_count",
                "dtls_heartbeat_idle_timeout", "dtls_heartbeat_interval",
                "dtls_hello_timeout", "http_request_body_timeout",
                "http_request_header_timeout", "login_timeout",
                "saml_redirect_port", "tunnel_user_session_timeout",
            } and values:
                try:
                    value = int(values[0])
                except ValueError:
                    self.config.ssl_vpn_settings.extra_settings.update(
                        sanitize_source_attributes({f"unparsed_{clean_key}": values[0]})
                    )
                    return
            else:
                value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in FGSSLVPNSettings.model_fields and clean_key not in {
                "authentication_rules",
                "extra_settings",
            }:
                setattr(self.config.ssl_vpn_settings, clean_key, value)
            else:
                self.config.ssl_vpn_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "user setting":
            if not self.config.user_authentication_settings:
                self.config.user_authentication_settings = FGUserAuthenticationSettings()
            clean_key = key.replace("-", "_")
            value: Any = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {
                "auth_timeout", "auth_lockout_threshold", "auth_lockout_duration",
            } and values:
                try:
                    value = int(values[0])
                except ValueError:
                    value = values[0]
            if clean_key == "auth_ssl_min_proto_version":
                self.config.user_authentication_settings.ssl_min_proto_version = value
                self.config.user_authentication_settings.extra_settings.update(
                    {clean_key: value}
                )
                return
            if clean_key in FGUserAuthenticationSettings.model_fields and clean_key != "extra_settings":
                setattr(self.config.user_authentication_settings, clean_key, value)
            else:
                self.config.user_authentication_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "user quarantine":
            if not self.config.user_quarantine:
                self.config.user_quarantine = FGUserQuarantine()
            clean_key = key.replace("-", "_")
            if clean_key == "firewall_groups":
                self.config.user_quarantine.firewall_groups = list(values)
            else:
                value = values[0] if len(values) == 1 else " ".join(values)
                self.config.user_quarantine.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "web-proxy global":
            if not self.config.web_proxy_global:
                self.config.web_proxy_global = FGWebProxyGlobal()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in FGWebProxyGlobal.model_fields and clean_key != "extra_settings":
                setattr(self.config.web_proxy_global, clean_key, value)
            else:
                self.config.web_proxy_global.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

    def apply_global_unset(self, section_path: str, key: str) -> None:
        clean_key = key.replace("-", "_")
        if section_path == "system settings":
            context = self._execution_context()
            if clean_key in {"central_nat", "ngfw_mode", "opmode"}:
                setattr(context, clean_key, None)
            context.extra_settings.pop(clean_key, None)
        elif section_path == "system session-ttl" and self.config.session_ttl_settings:
            if clean_key == "default":
                self.config.session_ttl_settings.default_timeout = None
            self.config.session_ttl_settings.extra_settings.pop(clean_key, None)
        elif section_path == "system global" and self.config.system_global:
            if clean_key == "hostname":
                self.config.system_global.hostname = None
            elif clean_key == "admin_sport":
                self.config.system_global.admin_sport = None
            elif clean_key == "timezone":
                self.config.system_global.timezone = None
            elif clean_key == "opmode":
                self._execution_context().opmode = None
            self.config.system_global.extra_settings.pop(clean_key, None)
        elif section_path == "system dns" and self.config.dns:
            if clean_key in {
                "primary", "secondary", "protocol", "server_select_method",
                "domain", "interface_select_method", "interface", "source_ip",
                "source_ip6", "ssl_certificate", "timeout", "retry",
            }:
                setattr(self.config.dns, clean_key, None)
            if clean_key == "primary":
                self.config.dns.primary = None
            elif clean_key == "secondary":
                self.config.dns.secondary = None
            self.config.dns.extra_settings.pop(clean_key, None)
        elif section_path == "web-proxy global" and self.config.web_proxy_global:
            if clean_key in FGWebProxyGlobal.model_fields and clean_key != "extra_settings":
                setattr(self.config.web_proxy_global, clean_key, None)
            self.config.web_proxy_global.extra_settings.pop(clean_key, None)
        elif section_path == "system sdwan":
            sdwan = self._sdwan_for_current_context()
            if clean_key == "status":
                sdwan.status = "disable"
            elif clean_key == "load_balance_mode":
                sdwan.load_balance_mode = None
            sdwan.extra_settings.pop(clean_key, None)
        elif section_path == "vpn ssl settings" and self.config.ssl_vpn_settings:
            if clean_key in SECTION_LIST_FIELDS["vpn ssl settings"]:
                setattr(self.config.ssl_vpn_settings, clean_key, [])
            elif clean_key in FGSSLVPNSettings.model_fields and clean_key not in {
                "authentication_rules",
                "extra_settings",
            }:
                setattr(self.config.ssl_vpn_settings, clean_key, None)
            self.config.ssl_vpn_settings.extra_settings.pop(clean_key, None)
        elif section_path == "user setting" and self.config.user_authentication_settings:
            if clean_key in FGUserAuthenticationSettings.model_fields and clean_key != "extra_settings":
                setattr(self.config.user_authentication_settings, clean_key, None)
            self.config.user_authentication_settings.extra_settings.pop(clean_key, None)
        elif section_path == "user quarantine" and self.config.user_quarantine:
            if clean_key == "firewall_groups":
                self.config.user_quarantine.firewall_groups = []
            self.config.user_quarantine.extra_settings.pop(clean_key, None)

    @staticmethod
    def _normalize_address_nested_entries(attributes: Dict[str, Any]) -> None:
        normalized_list = []
        for raw_entry in attributes.get("address_list", []):
            entry = dict(raw_entry)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGAddressListEntry.model_fields)
            )
            normalized_list.append(FGAddressListEntry(**entry))
        attributes["address_list"] = normalized_list

        normalized_tagging = []
        for raw_entry in attributes.get("tagging", []):
            entry = dict(raw_entry)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGAddressTaggingEntry.model_fields)
            )
            normalized_tagging.append(FGAddressTaggingEntry(**entry))
        attributes["tagging"] = normalized_tagging

    @staticmethod
    def _normalize_ssl_vpn_nested(attributes: Dict[str, Any]) -> None:
        def safe_entry(raw: Dict[str, Any], model: Any) -> Any:
            entry = dict(raw)
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(model.model_fields)
            )
            return model(**entry)

        split_dns = [
            safe_entry(item, FGSSLVPNPortalSplitDNS)
            for item in attributes.pop("split_dns", [])
        ]
        mac_rules = [
            safe_entry(item, FGSSLVPNPortalMACAddressRule)
            for item in attributes.pop("mac_address_check_rules", [])
        ]
        os_checks = [
            safe_entry(item, FGSSLVPNPortalOSCheck)
            for item in attributes.pop("os_check_list", [])
        ]

        def form_items(raw_items: List[Dict[str, Any]], model: Any) -> List[Any]:
            result = []
            for raw in raw_items:
                item = dict(raw)
                item.pop("value", None)
                item["value_configured"] = True
                result.append(safe_entry(item, model))
            return result

        bookmarks = []
        for raw_group in attributes.pop("bookmark_groups", []):
            group = dict(raw_group)
            raw_bookmarks = group.pop("bookmarks", [])
            group["bookmarks"] = []
            for raw_bookmark in raw_bookmarks:
                bookmark = dict(raw_bookmark)
                bookmark["has_logon_password"] = "logon_password" in bookmark
                bookmark["has_sso_password"] = "sso_password" in bookmark
                bookmark.pop("logon_password", None)
                bookmark.pop("sso_password", None)
                bookmark["form_data"] = form_items(
                    bookmark.pop("form_data", []), FGSSLVPNPortalBookmarkFormData
                )
                group["bookmarks"].append(safe_entry(bookmark, FGSSLVPNPortalBookmark))
            bookmarks.append(safe_entry(group, FGSSLVPNPortalBookmarkGroup))

        landing_pages = []
        for raw_page in attributes.pop("landing_pages", []):
            page = dict(raw_page)
            page["form_data"] = form_items(
                page.pop("form_data", []), FGSSLVPNPortalLandingPageFormData
            )
            landing_pages.append(safe_entry(page, FGSSLVPNPortalLandingPage))

        attributes.update({
            "bookmark_groups": bookmarks,
            "landing_pages": landing_pages,
            "mac_address_check_rules": mac_rules,
            "os_check_list": os_checks,
            "split_dns": split_dns,
        })

    def build_model(
        self,
        section_path: str,
        attributes: Dict[str, Any],
        
    ):
        if section_path in CONTEXTUAL_MODEL_SECTIONS:
            attributes.setdefault("source_context", self.current_context)
        if section_path == "system zone":
            self.config.system_zones.append(
                FGSystemZone(**attributes)
            )

        elif section_path == "system interface":
            attributes.setdefault("has_pppoe_password", False)
            attributes.setdefault("pppoe_password_format", None)
            explicit_vdom = attributes.get("vdom")
            effective_vdom = explicit_vdom or self.current_context
            attributes["vdom"] = effective_vdom
            attributes["source_context"] = effective_vdom
            for key in FG_INTERFACE_IPV6_INT_FIELDS:
                self._normalize_optional_int(attributes, key)
            # FortiOS stores interface VRF IDs as numeric values. Preserve
            # malformed values in source_attributes through the existing
            # unparsed_* convention instead of allowing model construction to
            # fail or inventing a default routing domain.
            if attributes.get("vrf") is True:
                attributes["unparsed_vrf"] = attributes.pop("vrf")
            else:
                self._normalize_optional_int(attributes, "vrf")

            # FortiOS calls this command ``member`` while the typed model uses
            # the plural form to make the ordered relationship explicit.
            # Keep the source command in inventory, but do not leave a second
            # generic copy in source_attributes.
            if "member" in attributes:
                attributes["members"] = attributes.pop("member")
            raw_secondary_ips = attributes.pop("secondary_ips", [])
            secondary_ips = []
            for raw_item in raw_secondary_ips:
                item = dict(raw_item)
                if "id" not in item and item.get("name", "").isdigit():
                    item["id"] = int(item["name"])
                if item.get("name") == str(item.get("id")):
                    item.pop("name", None)

                item["extra_settings"] = _extract_extra_settings(
                    item,
                    set(FGInterfaceSecondaryIP.model_fields),
                )
                secondary_ips.append(FGInterfaceSecondaryIP(**item))

            attributes["secondary_ips"] = secondary_ips
            raw_extra_addresses = attributes.pop("ipv6_extra_addresses", [])
            attributes["ipv6_extra_addresses"] = [
                item if isinstance(item, FGInterfaceIPv6ExtraAddress)
                else FGInterfaceIPv6ExtraAddress(**item)
                for item in raw_extra_addresses
            ]

            explicit_settings = {
                key: value
                for key, value in attributes.items()
                if key not in {
                    "name",
                    "id",
                    "members",
                    "secondary_ips",
                    "ipv6_extra_addresses",
                    "ipv6_prefix_advertisements",
                    "ipv6_delegated_prefix_advertisements",
                    "dhcp6_iapd",
                    "vrrp6",
                    "nested_configs",
                    "ipv6_source_settings",
                    "ip6_address",
                    "ip6_allowaccess",
                    "ip6_mode",
                    "ip6_send_adv",
                    "ip6_manage_flag",
                    "ip6_other_flag",
                    "ipv6_autoconf", *FG_INTERFACE_IPV6_SCALAR_FIELDS,
                    *FG_INTERFACE_IPV6_LIST_FIELDS,
                    "has_pppoe_password",
                    "pppoe_password_format",
                }
            }

            attributes["source_attributes"] = (
                sanitize_source_attributes(
                    explicit_settings
                )
            )
            attributes.pop("password", None)

            self.config.interfaces.append(
                FGInterface(**attributes)
            )

        elif section_path == "firewall address":
            self._normalize_optional_int(attributes, "cache_ttl")
            self._normalize_optional_int(attributes, "route_tag")
            self._normalize_address_nested_entries(attributes)
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddress.model_fields),
                )
            )

            self.config.addresses.append(
                FGAddress(**attributes)
            )

        elif section_path == "firewall address6":
            attributes["is_ipv6"] = True
            self._normalize_optional_int(attributes, "cache_ttl")
            self._normalize_optional_int(attributes, "route_tag")
            self._normalize_address_nested_entries(attributes)
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddress.model_fields),
                )
            )

            self.config.addresses.append(
                FGAddress(**attributes)
            )

        elif section_path == "firewall multicast-address6":
            attributes["is_ipv6"] = True
            attributes["is_multicast"] = True
            self._normalize_optional_int(attributes, "cache_ttl")
            self._normalize_optional_int(attributes, "route_tag")
            self._normalize_address_nested_entries(attributes)
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddress.model_fields),
                )
            )

            self.config.addresses.append(
                FGAddress(**attributes)
            )

        elif section_path == "firewall multicast-address":
            attributes["is_multicast"] = True
            self._normalize_optional_int(attributes, "cache_ttl")
            self._normalize_optional_int(attributes, "route_tag")
            self._normalize_address_nested_entries(attributes)
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddress.model_fields),
                )
            )

            self.config.addresses.append(
                FGAddress(**attributes)
            )

        elif section_path in {"firewall addrgrp", "firewall addrgrp6"}:
            tagging = []
            for entry in attributes.get("tagging", []):
                entry["extra_settings"] = _extract_extra_settings(
                    entry, set(FGAddressGroupTaggingEntry.model_fields)
                )
                tagging.append(FGAddressGroupTaggingEntry(**entry))
            attributes["tagging"] = tagging
            attributes["is_ipv6"] = section_path == "firewall addrgrp6"
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddressGroup.model_fields),
                )
            )

            self.config.address_groups.append(
                FGAddressGroup(**attributes)
            )

        elif section_path == "firewall wildcard-fqdn custom":
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGWildcardFQDN.model_fields),
                )
            )

            self.config.wildcard_fqdns.append(
                FGWildcardFQDN(**attributes)
            )

        elif section_path == "firewall service category":
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGServiceCategory.model_fields),
                )
            )

            self.config.service_categories.append(
                FGServiceCategory(**attributes)
            )

        elif section_path == "firewall service custom":
            attributes["source_protocol_configured"] = attributes.get(
                "protocol"
            )
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGService.model_fields),
                )
            )

            self.config.services.append(
                FGService(**attributes)
            )

        elif section_path == "firewall service group":
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGServiceGroup.model_fields),
                )
            )

            self.config.service_groups.append(
                FGServiceGroup(**attributes)
            )

        elif section_path in {
            "firewall schedule recurring",
            "firewall schedule onetime",
        }:
            attributes["type"] = (
                "onetime" if section_path.endswith("onetime") else "recurring"
            )
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSchedule.model_fields),
            )
            self.config.schedules.append(
                FGSchedule(**attributes)
            )

        elif section_path == "firewall schedule group":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes, set(FGScheduleGroup.model_fields)
            )
            self.config.schedule_groups.append(FGScheduleGroup(**attributes))

        elif section_path == "firewall shaper traffic-shaper":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGTrafficShaper.model_fields),
            )
            self.config.traffic_shapers.append(
                FGTrafficShaper(**attributes)
            )

        elif section_path == "firewall proxy-address":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGProxyAddress.model_fields),
            )
            self.config.proxy_addresses.append(
                FGProxyAddress(**attributes)
            )

        elif section_path == "firewall ippool":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGIPPool.model_fields),
            )
            self.config.ip_pools.append(
                FGIPPool(**attributes)
            )

        elif section_path == "firewall ippool6":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGIPPool6.model_fields),
            )
            self.config.ip_pools6.append(FGIPPool6(**attributes))

        elif section_path in {"firewall vip", "firewall vip6"}:
            raw_realservers = attributes.pop("realservers", [])
            realservers = []
            for raw_server in raw_realservers:
                server = dict(raw_server)
                if server.get("name") == str(server.get("id")):
                    server.pop("name", None)
                server["extra_settings"] = _extract_extra_settings(
                    server,
                    set(FGVIPRealServer.model_fields),
                )
                realservers.append(FGVIPRealServer(**server))
            attributes["realservers"] = realservers

            vip_model = FGVIP if section_path == "firewall vip" else FGVIP6
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(vip_model.model_fields),
                )
            )

            if section_path == "firewall vip":
                self.config.vips.append(FGVIP(**attributes))
            else:
                self.config.vips6.append(FGVIP6(**attributes))

        elif section_path == "firewall vipgrp":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGVIPGroup.model_fields),
            )
            self.config.vip_groups.append(
                FGVIPGroup(**attributes)
            )

        elif section_path == "firewall vipgrp6":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGVIPGroup6.model_fields),
            )
            self.config.vip_groups6.append(FGVIPGroup6(**attributes))

        elif section_path == "firewall policy":
            compatibility_internet_service_settings = {
                key: list(attributes[key])
                for key in (
                    "internet_service_custom", "internet_service_custom_group",
                    "internet_service_src_custom", "internet_service_src_custom_group",
                    "internet_service6_custom", "internet_service6_custom_group",
                    "internet_service6_src_custom", "internet_service6_src_custom_group",
                )
                if attributes.get(key)
            }
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGPolicy.model_fields),
                )
            )
            attributes["extra_settings"].update(compatibility_internet_service_settings)

            self.config.policies.append(
                FGPolicy(**attributes)
            )

        elif section_path in {"firewall multicast-policy", "firewall multicast-policy6"}:
            self._source_order += 1
            attributes["source_order"] = self._source_order
            attributes["extra_settings"] = _extract_extra_settings(
                attributes, set(FGMulticastPolicy.model_fields)
            )
            target = self.config.multicast_policies6 if section_path.endswith("6") else self.config.multicast_policies
            target.append(FGMulticastPolicy(**attributes))

        elif section_path == "firewall central-snat-map":
            self._source_order += 1
            attributes["source_order"] = self._source_order
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes, set(FGCentralSNATRule.model_fields)
            )
            self.config.central_snat_rules.append(FGCentralSNATRule(**attributes))

        elif section_path == "firewall ip-translation":
            self._source_order += 1
            attributes["source_order"] = self._source_order
            attributes["extra_settings"] = _extract_extra_settings(
                attributes, set(FGIPTranslation.model_fields)
            )
            self.config.ip_translations.append(FGIPTranslation(**attributes))

        elif section_path in SOURCE_ONLY_RULE_FAMILIES:
            self._source_order += 1
            rule_id = attributes.pop("id", None)
            name = attributes.pop("name", None)
            context = attributes.pop("source_context", self.current_context)
            status = attributes.get("status")
            nested_configs = attributes.pop("nested_configs", [])
            settings = sanitize_source_attributes(attributes)
            rule = FGSourceOnlyRule(
                family=SOURCE_ONLY_RULE_FAMILIES[section_path],
                id=rule_id,
                name=name,
                source_order=self._source_order,
                status=status,
                source_context=context,
                settings=settings,
                nested_configs=nested_configs,
            )
            target = {
                "firewall security-policy": self.config.security_policies,
                "router policy": self.config.policy_routes,
                "router policy6": self.config.policy_routes,
                "firewall local-in-policy": self.config.local_in_policies,
                "firewall local-in-policy6": self.config.local_in_policies,
                "firewall proxy-policy": self.config.proxy_policies,
                "firewall shaping-policy": self.config.shaping_policies,
                "system dhcp6 server": self.config.dhcp6_servers,
                "firewall internet-service-custom": self.config.custom_internet_services,
                "firewall internet-service-custom-group": self.config.custom_internet_service_groups,
            }.get(section_path, self.config.source_only_rules)
            target.append(rule)

        elif section_path == "ips sensor":
            raw_entries = attributes.pop("entries", [])
            entries = []

            for raw_entry in raw_entries:
                entry = dict(raw_entry)
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)

                raw_rules = entry.pop("rule", [])
                if not isinstance(raw_rules, list):
                    raw_rules = [raw_rules]

                rules = []
                unparsed_rules = []
                for value in raw_rules:
                    try:
                        rules.append(int(value))
                    except (TypeError, ValueError):
                        unparsed_rules.append(value)

                entry["rules"] = rules
                if unparsed_rules:
                    entry["unparsed_rule_values"] = unparsed_rules

                for numeric_field in (
                    "rate_count",
                    "rate_duration",
                ):
                    raw_value = entry.get(numeric_field)
                    if raw_value is None:
                        continue
                    try:
                        entry[numeric_field] = int(raw_value)
                    except (TypeError, ValueError):
                        entry.pop(numeric_field, None)
                        entry[
                            f"unparsed_{numeric_field}"
                        ] = raw_value

                raw_vuln_types = entry.get("vuln_type", [])
                vuln_types = []
                for value in raw_vuln_types:
                    try:
                        vuln_types.append(int(value))
                    except (TypeError, ValueError):
                        entry.setdefault("unparsed_vuln_type", []).append(value)
                entry["vuln_type"] = vuln_types
                entry["exempt_ips"] = [
                    FGIPSSensorExemptIP(**exempt)
                    for exempt in entry.get("exempt_ips", [])
                ]

                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGIPSSensorEntry.model_fields),
                )
                entries.append(FGIPSSensorEntry(**entry))

            attributes["entries"] = entries
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGIPSSensor.model_fields),
            )
            self.config.ips_sensors.append(
                FGIPSSensor(**attributes)
            )

        elif section_path == "vpn ipsec phase1-interface":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGPhase1Interface.model_fields),
            )
            self.config.phase1_interfaces.append(
                FGPhase1Interface(**attributes)
            )

        elif section_path == "vpn ipsec phase2-interface":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGPhase2Interface.model_fields),
            )
            self.config.phase2_interfaces.append(
                FGPhase2Interface(**attributes)
            )

        elif section_path in {
            "vpn certificate remote",
            "vpn certificate local",
            "vpn certificate ca",
        }:
            attributes["certificate_type"] = section_path.rsplit(" ", 1)[-1]
            raw_last_updated = attributes.get("last_updated")
            if raw_last_updated is not None:
                try:
                    attributes["last_updated"] = int(raw_last_updated)
                except (TypeError, ValueError):
                    attributes.pop("last_updated", None)
                    attributes["last_updated_raw"] = raw_last_updated

            public_certificate = attributes.get("public_certificate")

            if public_certificate:
                attributes.update(
                    parse_certificate_metadata(public_certificate)
                )

            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGCertificate.model_fields),
            )
            self.config.certificates.append(
                FGCertificate(**attributes)
            )

        elif section_path in {
            "firewall ssh local-key",
            "firewall ssh local-ca",
        }:
            attributes["key_type"] = section_path.rsplit(" ", 1)[-1]
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSSHKey.model_fields),
            )
            self.config.ssh_keys.append(FGSSHKey(**attributes))

        elif section_path in {"router static", "router static6"}:
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["address_family"] = (
                "ipv6" if section_path == "router static6" else "ipv4"
            )
            for field in (
                "distance",
                "priority",
                "weight",
                "vrf",
                "tag",
                "internet_service",
            ):
                self._normalize_optional_int(attributes, field)
                # Do not let an invalid explicitly supplied value fall back
                # to the FortiOS effective default.  The unparsed value is
                # retained in extra_settings for manual review.
                if f"unparsed_{field}" in attributes:
                    attributes[field] = None
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGStaticRoute.model_fields),
            )
            self.config.static_routes.append(
                FGStaticRoute(**attributes)
            )

        elif section_path == "system sdwan zone":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context

            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanZone.model_fields),
            )
            sdwan.zones.append(
                FGSDWanZone(**attributes)
            )

        elif section_path == "system sdwan members":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context

            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            for field in (
                "cost",
                "weight",
                "priority",
                "priority6",
                "spillover_threshold",
                "ingress_spillover_threshold",
                "volume_ratio",
            ):
                self._normalize_optional_int(attributes, field)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanMember.model_fields),
            )
            sdwan.members.append(
                FGSDWanMember(**attributes)
            )

        elif section_path == "system sdwan health-check":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context
            self._normalize_int_list(attributes, "members")
            for field in (
                "port",
                "interval",
                "probe_timeout",
                "failtime",
                "recoverytime",
                "vrf",
            ):
                self._normalize_optional_int(attributes, field)
            raw_sla = attributes.pop("sla", [])
            sla = []
            for entry in raw_sla:
                entry["source_context"] = sdwan.source_context
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)
                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGSDWanSLA.model_fields),
                )
                sla.append(FGSDWanSLA(**entry))
            attributes["sla"] = sla
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanHealthCheck.model_fields),
            )
            sdwan.health_checks.append(
                FGSDWanHealthCheck(**attributes)
            )

        elif section_path == "system sdwan service":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context
            if attributes.get("name") == str(attributes.get("id")):
                attributes["name"] = None
            self._normalize_int_list(attributes, "priority_members")
            self._normalize_int_list(attributes, "internet_service_app_ctrl")
            raw_sla = attributes.pop("sla", [])
            sla = []
            for entry in raw_sla:
                entry["source_context"] = sdwan.source_context
                source_name = str(entry.get("name", entry.get("id", "")))
                entry["name"] = source_name
                self._normalize_optional_int(entry, "id")
                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGSDWanServiceSLA.model_fields),
                )
                sla.append(FGSDWanServiceSLA(**entry))
            attributes["sla"] = sla
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanService.model_fields),
            )
            sdwan.services.append(FGSDWanService(**attributes))

        elif section_path == "system sdwan duplication":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            self._normalize_optional_int(attributes, "service_id")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanDuplication.model_fields),
            )
            sdwan.duplication_rules.append(
                FGSDWanDuplication(**attributes)
            )

        elif section_path == "system sdwan neighbor":
            sdwan = self._sdwan_for_current_context()
            attributes["source_context"] = sdwan.source_context
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanNeighbor.model_fields),
            )
            sdwan.neighbors.append(FGSDWanNeighbor(**attributes))

        elif section_path == "firewall internet-service-name":
            source_id = attributes.pop(
                "internet_service_id",
                None,
            )

            if source_id is not None:
                try:
                    attributes["id"] = int(
                        source_id
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    attributes["id"] = None
                    attributes[
                        "unparsed_internet_service_id"
                    ] = source_id

            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGInternetService.model_fields),
            )

            self.config.internet_services.append(
                FGInternetService(
                    **attributes
                )
            )

        elif section_path == "firewall internet-service-definition":
            attributes.pop("name", None)
            raw_entries = attributes.pop("entries", [])
            entries = []
            for entry_attributes in raw_entries:
                entry_attributes["seq_num"] = entry_attributes.pop("id", None)
                if entry_attributes.get("name") == str(entry_attributes["seq_num"]):
                    entry_attributes.pop("name", None)
                raw_port_ranges = entry_attributes.pop("port_ranges", [])
                port_ranges = []
                for range_attributes in raw_port_ranges:
                    range_attributes.pop("name", None)
                    self._normalize_optional_int(range_attributes, "start_port")
                    self._normalize_optional_int(range_attributes, "end_port")
                    range_attributes["extra_settings"] = _extract_extra_settings(
                        range_attributes,
                        set(FGInternetServiceDefinitionPortRange.model_fields),
                    )
                    port_ranges.append(FGInternetServiceDefinitionPortRange(**range_attributes))
                entry_attributes["port_ranges"] = port_ranges
                self._normalize_optional_int(entry_attributes, "category_id")
                self._normalize_optional_int(entry_attributes, "protocol")
                entry_attributes["extra_settings"] = _extract_extra_settings(
                    entry_attributes,
                    set(FGInternetServiceDefinitionEntry.model_fields),
                )
                entries.append(FGInternetServiceDefinitionEntry(**entry_attributes))
            attributes["entries"] = entries
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGInternetServiceDefinition.model_fields),
            )
            self.config.internet_service_definitions.append(
                FGInternetServiceDefinition(**attributes)
            )
        
        elif section_path == "endpoint-control fctems":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGFCTEMS.model_fields),
            )

            self.config.fctems_connectors.append(
                FGFCTEMS(**attributes)
            )

        elif section_path == "user ldap":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGUserLDAP.model_fields),
            )
            self.config.user_ldap_servers.append(FGUserLDAP(**attributes))

        elif section_path == "user fsso":
            provider_has_password = attributes.get("has_password", False)
            endpoints = []
            for index in range(1, 6):
                suffix = "" if index == 1 else str(index)
                server = attributes.get(f"server{suffix}")
                port = attributes.get(f"port{suffix}")
                password = attributes.pop(f"password{suffix}", None)
                password_configured = attributes.pop(
                    f"has_password{suffix}",
                    attributes.get("has_password", False) if index == 1 else False,
                )
                if server is not None or port is not None or password is not None or password_configured:
                    self._normalize_optional_int(attributes, f"port{suffix}")
                    endpoints.append(FGFSSOEndpoint(
                        index=index,
                        server=server,
                        port=attributes.get(f"port{suffix}"),
                        has_password=bool(password) or bool(password_configured),
                    ))
            attributes["endpoints"] = endpoints
            attributes["has_password"] = provider_has_password
            for field in ("group_poll_interval", "ldap_poll_interval", "logon_timeout"):
                self._normalize_optional_int(attributes, field)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGFSSOServer.model_fields),
            )
            self.config.fsso_servers.append(FGFSSOServer(**attributes))

        elif section_path == "user adgrp":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGADGroup.model_fields),
            )
            self.config.ad_groups.append(FGADGroup(**attributes))

        elif section_path == "user saml":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGUserSAML.model_fields),
            )
            self.config.user_saml_servers.append(FGUserSAML(**attributes))

        elif section_path == "user local":
            self._normalize_optional_int(attributes, "id")
            self._normalize_optional_int(attributes, "auth_concurrent_value")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGLocalUser.model_fields),
            )
            self.config.local_users.append(FGLocalUser(**attributes))

        elif section_path == "user group":
            if "type" in attributes:
                attributes["group_type"] = attributes.pop("type")
            raw_matches = attributes.pop("match", [])
            raw_guests = attributes.pop("guests", [])
            matches = []
            for entry in raw_matches:
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)
                matches.append(FGUserGroupMatch(**entry))
            attributes["match"] = matches
            guests = []
            for entry in raw_guests:
                entry["id"] = entry.get("id", entry.get("name"))
                self._normalize_optional_int(entry, "id")
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)
                entry["extra_settings"] = _extract_extra_settings(
                    entry, set(FGUserGroupGuest.model_fields)
                )
                guests.append(FGUserGroupGuest(**entry))
            attributes["guests"] = guests
            for field in ("id", "auth_concurrent_value", "authtimeout", "expire", "max_accounts"):
                self._normalize_optional_int(attributes, field)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGUserGroup.model_fields),
            )
            self.config.user_groups.append(FGUserGroup(**attributes))

        elif section_path == "system admin":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGAdministrator.model_fields),
            )
            self.config.administrators.append(FGAdministrator(**attributes))

        elif section_path == "system accprofile":
            raw_permission_blocks = attributes.pop("permission_blocks", [])
            permission_blocks = []
            known_permission_settings = {
                "fwgrp_permission": {"policy", "address", "service", "schedule", "others"},
                "loggrp_permission": {"config", "data_access", "report_access", "threat_weight"},
                "netgrp_permission": {"cfg", "packet_capture", "route_cfg"},
                "sysgrp_permission": {"admin", "upd", "cfg", "mnt"},
            }
            for block in raw_permission_blocks:
                settings = dict(block.get("settings", {}))
                known_keys = known_permission_settings.get(
                    block["name"].replace("-", "_"), set(settings)
                )
                permission_blocks.append(
                    FGAdminProfilePermissionBlock(
                        name=block["name"],
                        settings={key: value for key, value in settings.items() if key in known_keys},
                        extra_settings=sanitize_source_attributes({
                            key: value for key, value in settings.items() if key not in known_keys
                        }),
                    )
                )
            attributes["permission_blocks"] = permission_blocks
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGAdminProfile.model_fields),
            )
            self.config.admin_profiles.append(FGAdminProfile(**attributes))

        elif section_path == "user fortitoken":
            attributes["serial"] = attributes.pop("name")
            attributes.pop("id", None)
            if "user" in attributes:
                attributes["assigned_user"] = attributes.pop("user")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGFortiToken.model_fields),
            )
            self.config.fortitokens.append(FGFortiToken(**attributes))

        elif section_path == "vpn ssl web portal":
            for field in {
                "default_window_height", "default_window_width",
            }:
                self._normalize_optional_int(attributes, field)
            self._normalize_ssl_vpn_nested(attributes)
            raw_checks = attributes.pop("host_checks", [])
            host_checks = []
            for entry in raw_checks:
                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGSSLVPNHostCheckSoftware.model_fields),
                )
                host_checks.append(FGSSLVPNHostCheckSoftware(**entry))
            attributes["host_checks"] = host_checks
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSSLVPNPortal.model_fields),
            )
            self.config.ssl_vpn_portals.append(FGSSLVPNPortal(**attributes))

        elif section_path == "vpn ssl web host-check-software":
            raw_items = attributes.pop("check_items", [])
            check_items = []
            for entry in raw_items:
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)
                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGSSLVPNHostCheckItem.model_fields),
                )
                check_items.append(FGSSLVPNHostCheckItem(**entry))
            attributes["check_items"] = check_items
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSSLVPNHostCheckSoftware.model_fields),
            )
            self.config.ssl_vpn_host_check_software.append(
                FGSSLVPNHostCheckSoftware(**attributes)
            )

        elif section_path in {"firewall DoS-policy", "firewall DoS-policy6"}:
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["source_context"] = self.current_context
            attributes["address_family"] = (
                "ipv6" if section_path == "firewall DoS-policy6" else "ipv4"
            )
            raw_anomalies = attributes.pop("anomalies", [])
            anomalies = []
            for entry in raw_anomalies:
                self._normalize_optional_int(entry, "threshold")
                entry["extra_settings"] = _extract_extra_settings(
                    entry,
                    set(FGDoSAnomaly.model_fields),
                )
                anomalies.append(FGDoSAnomaly(**entry))
            attributes["anomalies"] = anomalies
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGDoSPolicy.model_fields),
            )
            self.config.dos_policies.append(FGDoSPolicy(**attributes))

        elif section_path == "firewall sniffer":
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGFirewallSniffer.model_fields),
            )
            self.config.firewall_sniffers.append(FGFirewallSniffer(**attributes))

        elif section_path == "authentication scheme":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGAuthenticationScheme.model_fields),
            )
            self.config.authentication_schemes.append(
                FGAuthenticationScheme(**attributes)
            )

        elif section_path == "authentication rule":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGAuthenticationRule.model_fields),
            )
            self.config.authentication_rules.append(
                FGAuthenticationRule(**attributes)
            )

        elif section_path == "system session-helper":
            if attributes.get("name") == str(attributes.get("id")):
                attributes["name"] = None
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSessionHelper.model_fields),
            )
            self.config.session_helpers.append(FGSessionHelper(**attributes))

        elif section_path == "system session-ttl port":
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSessionTTLOverride.model_fields),
            )
            self.config.session_ttl_overrides.append(
                FGSessionTTLOverride(**attributes)
            )

        elif section_path == "system dhcp server":
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)

            raw_ip_ranges = attributes.pop("ip_ranges", [])
            ip_ranges = []
            for range_attributes in raw_ip_ranges:
                if range_attributes.get("name") == str(range_attributes.get("id")):
                    range_attributes.pop("name", None)
                range_attributes["extra_settings"] = _extract_extra_settings(
                    range_attributes,
                    set(FGDHCPIPRange.model_fields),
                )
                ip_ranges.append(FGDHCPIPRange(**range_attributes))

            raw_exclude_ranges = attributes.pop("exclude_ranges", [])
            exclude_ranges = []
            for range_attributes in raw_exclude_ranges:
                if range_attributes.get("name") == str(range_attributes.get("id")):
                    range_attributes.pop("name", None)
                range_attributes["extra_settings"] = _extract_extra_settings(
                    range_attributes,
                    set(FGDHCPExcludeRange.model_fields),
                )
                exclude_ranges.append(FGDHCPExcludeRange(**range_attributes))

            raw_reservations = attributes.pop("reserved_addresses", [])
            reserved_addresses = []
            for reservation_attributes in raw_reservations:
                if reservation_attributes.get("name") == str(reservation_attributes.get("id")):
                    reservation_attributes.pop("name", None)
                reservation_attributes["extra_settings"] = _extract_extra_settings(
                    reservation_attributes,
                    set(FGDHCPReservation.model_fields),
                )
                reserved_addresses.append(FGDHCPReservation(**reservation_attributes))

            raw_options = attributes.pop("options", [])
            options = []
            for option_attributes in raw_options:
                if option_attributes.get("name") == str(option_attributes.get("id")):
                    option_attributes.pop("name", None)
                option_attributes["extra_settings"] = _extract_extra_settings(
                    option_attributes,
                    set(FGDHCPOption.model_fields),
                )
                options.append(FGDHCPOption(**option_attributes))

            attributes["ip_ranges"] = ip_ranges
            attributes["exclude_ranges"] = exclude_ranges
            attributes["reserved_addresses"] = reserved_addresses
            attributes["options"] = options
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGDHCPServer.model_fields),
            )
            self.config.dhcp_servers.append(FGDHCPServer(**attributes))


def parse_fortigate_config(
    text: str,
) -> FGConfig:
    tokenizer = FortiGateTokenizer(text)
    parser = FortiGateParser(tokenizer)

    return parser.parse()
