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
    FGSystemZone,
    FGAddress,
    FGAddressGroup,
    FGWildcardFQDN,
    FGServiceCategory,
    FGService,
    FGServiceGroup,
    FGSchedule,
    FGTrafficShaper,
    FGProxyAddress,
    FGWebProxyGlobal,
    FGIPPool,
    FGVIP,
    FGVIPGroup,
    FGPolicy,
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
    FGInternetService,
    FGFCTEMS,
    FGSessionHelper,
    FGSessionTTLOverride,
    FGDHCPServer,
    FGDHCPIPRange,
    FGDHCPReservation,
    FGCertificate,
    FGSSHKey,
    FGIPSSensor,
    FGIPSSensorEntry,
    FGUserLDAP,
    FGFSSOServer,
    FGADGroup,
    FGUserSAML,
    FGLocalUser,
    FGUserGroup,
    FGUserGroupMatch,
    FGAdministrator,
    FGAdminProfile,
    FGFortiToken,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
    FGSSLVPNAuthenticationRule,
    FGSSLVPNHostCheckSoftware,
    FGDoSPolicy,
    FGDoSAnomaly,
    FGFirewallSniffer,
    FGAuthenticationScheme,
    FGAuthenticationRule,
)
from fwmigrate.parsers.fortigate.certificates import parse_certificate_metadata
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.source_tree import (
    FGSourceCommand,
    FGSourceNode,
    FGStructuredSourceObject,
    STRUCTURED_ROUTING_SECTIONS,
    STRUCTURED_SECURITY_SECTIONS,
)


SECTION_LIST_FIELDS = {
    "system admin": {"vdom"},
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
    },
    "system sdwan health-check": {"members"},
    "system sdwan service": {
        "src",
        "dst",
        "priority_members",
        "internet_service_name",
        "internet_service_app_ctrl",
    },
    "vpn ssl web portal": {"ip_pools", "ipv6_pools"},
    "vpn ssl settings": {
        "banned_cipher",
        "source_interface",
        "source_address",
        "tunnel_ip_pools",
    },
    "vpn ssl settings authentication-rule": {"groups"},
    "firewall DoS-policy": {"srcaddr", "dstaddr", "service"},
    "authentication rule": {"srcintf", "srcaddr"},
}

IDENTITY_SECTIONS = {"user ldap", "user saml", "user local", "user fsso"}
IDENTITY_SECRET_FIELDS = {
    "password",
    "passwd",
    "seed",
    "activation_code",
    "private_key",
}
ADMIN_SECRET_FIELDS = IDENTITY_SECRET_FIELDS | {"secret"}

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

    def peek(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def next_token(self) -> Optional[Token]:
        token = self.peek()
        if token:
            self.pos += 1
        return token

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
        if full_path in STRUCTURED_SECURITY_SECTIONS | STRUCTURED_ROUTING_SECTIONS:
            self._parse_structured_source_section(full_path)
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
                    commands=source_commands,
                )
            )

    def _parse_structured_source_section(self, source_path: str) -> None:
        root = self.parse_source_node("config", source_path)
        top_edits = [child for child in root.children if child.node_type == "edit"]
        objects = [
            FGStructuredSourceObject(
                source_path=source_path,
                name=child.name,
                source_id=child.name if child.name.isdigit() else None,
                root=child,
            )
            for child in top_edits
        ]
        if root.commands or any(child.node_type != "edit" for child in root.children):
            objects.append(FGStructuredSourceObject(source_path=source_path, root=root))

        for source_object in objects:
            self.structured_source_objects.append(source_object)
            inventory = self._source_node_inventory(
                source_object.root,
                source_path,
                source_object.name,
            )
            inventory.notes.append(
                "structured-routing-protocol"
                if source_path in STRUCTURED_ROUTING_SECTIONS
                else "structured-security-profile"
            )
            self.source_inventory_items.append(inventory)

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
                self._source_node_inventory(child, source_path, child.name)
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

                source_commands.append(
                    self._source_command("set", key, values)
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
                    section_path == "firewall vip"
                    and nested_name == "realservers"
                ):
                    attributes["realservers"] = (
                        self.parse_nested_edit_collection(
                            nested_path
                        )
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
                    and nested_name == "reserved-address"
                ):
                    attributes["reserved_addresses"] = (
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

                elif (
                    section_path == "system sdwan health-check"
                    and nested_name == "sla"
                ):
                    attributes["sla"] = self.parse_nested_edit_collection(nested_path)

                elif section_path == "user group" and nested_name == "match":
                    attributes["match"] = self.parse_nested_edit_collection(nested_path)

                elif (
                    section_path == "vpn ssl web portal"
                    and nested_name == "host-check-software"
                ):
                    attributes["host_checks"] = self.parse_nested_edit_collection(nested_path)

                elif (
                    section_path == "firewall DoS-policy"
                    and nested_name == "anomaly"
                ):
                    attributes["anomalies"] = self.parse_nested_edit_collection(nested_path)

                elif nested_name:
                    self.parse_config_contents(
                        nested_path
                    )

            else:
                self.next_token()

        self.source_inventory_items.append(
            SourceInventoryItem(
                domain=section_path.split(" ", 1)[0] if section_path else "unknown",
                source_path=section_path,
                name=item_name,
                source_id=item_name if item_name.isdigit() else None,
                commands=source_commands,
            )
        )
        return attributes

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

    def apply_append_attribute(
        self,
        attributes: Dict[str, Any],
        key: str,
        values: List[str],
        section_path: str = "",
    ) -> None:
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
        clean_key = self._normalize_attribute_key(key)

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

        if section_path == "system admin" and clean_key in ADMIN_SECRET_FIELDS:
            attributes["credential_configured"] = bool(values)
            return

        if section_path == "user fortitoken" and clean_key in ADMIN_SECRET_FIELDS:
            return

        if section_path in IDENTITY_SECTIONS and clean_key in IDENTITY_SECRET_FIELDS:
            if clean_key in {"password", "passwd"}:
                attributes["has_password"] = True
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
        if section_path == "system global":
            if not self.config.system_global:
                self.config.system_global = (
                    FGSystemGlobal(
                        hostname="unknown"
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

            elif clean_key != "extra_settings":
                self.config.system_global.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system dns":
            if not self.config.dns:
                self.config.dns = FGDns()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"primary", "secondary"} and values:
                setattr(self.config.dns, clean_key, values[0])
            elif clean_key != "extra_settings":
                self.config.dns.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system sdwan":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"status", "load_balance_mode"} and values:
                setattr(self.config.sdwan, clean_key, value)
            elif clean_key != "extra_settings":
                self.config.sdwan.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "vpn ssl settings":
            if not self.config.ssl_vpn_settings:
                self.config.ssl_vpn_settings = FGSSLVPNSettings()
            clean_key = key.replace("-", "_")
            if clean_key in SECTION_LIST_FIELDS["vpn ssl settings"]:
                value: Any = list(values)
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
        if section_path == "system global" and self.config.system_global:
            if clean_key == "hostname":
                self.config.system_global.hostname = "unknown"
            elif clean_key == "admin_sport":
                self.config.system_global.admin_sport = None
            elif clean_key == "timezone":
                self.config.system_global.timezone = None
            else:
                self.config.system_global.extra_settings.pop(clean_key, None)
        elif section_path == "system dns" and self.config.dns:
            if clean_key == "primary":
                self.config.dns.primary = None
            elif clean_key == "secondary":
                self.config.dns.secondary = None
            else:
                self.config.dns.extra_settings.pop(clean_key, None)
        elif section_path == "web-proxy global" and self.config.web_proxy_global:
            if clean_key in FGWebProxyGlobal.model_fields and clean_key != "extra_settings":
                setattr(self.config.web_proxy_global, clean_key, None)
            else:
                self.config.web_proxy_global.extra_settings.pop(clean_key, None)
        elif section_path == "system sdwan" and self.config.sdwan:
            if clean_key == "status":
                self.config.sdwan.status = "disable"
            elif clean_key == "load_balance_mode":
                self.config.sdwan.load_balance_mode = None
            else:
                self.config.sdwan.extra_settings.pop(clean_key, None)
        elif section_path == "vpn ssl settings" and self.config.ssl_vpn_settings:
            if clean_key in SECTION_LIST_FIELDS["vpn ssl settings"]:
                setattr(self.config.ssl_vpn_settings, clean_key, [])
            elif clean_key in FGSSLVPNSettings.model_fields and clean_key not in {
                "authentication_rules",
                "extra_settings",
            }:
                setattr(self.config.ssl_vpn_settings, clean_key, None)
            else:
                self.config.ssl_vpn_settings.extra_settings.pop(clean_key, None)

    def build_model(
        self,
        section_path: str,
        attributes: Dict[str, Any],
        
    ):
        if section_path == "system zone":
            self.config.system_zones.append(
                FGSystemZone(**attributes)
            )

        elif section_path == "system interface":
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

            explicit_settings = {
                key: value
                for key, value in attributes.items()
                if key not in {"name", "id", "secondary_ips"}
            }

            attributes["source_attributes"] = (
                sanitize_source_attributes(
                    explicit_settings
                )
            )

            self.config.interfaces.append(
                FGInterface(**attributes)
            )

        elif section_path == "firewall address":
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
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGAddress.model_fields),
                )
            )

            self.config.addresses.append(
                FGAddress(**attributes)
            )

        elif section_path == "firewall addrgrp":
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
            self.config.ip_pools.append(
                FGIPPool(**attributes)
            )

        elif section_path == "firewall vip":
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGVIP.model_fields),
                )
            )

            self.config.vips.append(
                FGVIP(**attributes)
            )

        elif section_path == "firewall vipgrp":
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGVIPGroup.model_fields),
            )
            self.config.vip_groups.append(
                FGVIPGroup(**attributes)
            )

        elif section_path == "firewall policy":
            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGPolicy.model_fields),
                )
            )

            self.config.policies.append(
                FGPolicy(**attributes)
            )

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

        elif section_path == "router static":
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            self._normalize_optional_int(attributes, "distance")
            self._normalize_optional_int(attributes, "priority")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGStaticRoute.model_fields),
            )
            self.config.static_routes.append(
                FGStaticRoute(**attributes)
            )

        elif section_path == "system sdwan zone":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()

            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanZone.model_fields),
            )
            self.config.sdwan.zones.append(
                FGSDWanZone(**attributes)
            )

        elif section_path == "system sdwan members":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()

            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            self._normalize_optional_int(attributes, "weight")
            self._normalize_optional_int(attributes, "priority")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanMember.model_fields),
            )
            self.config.sdwan.members.append(
                FGSDWanMember(**attributes)
            )

        elif section_path == "system sdwan health-check":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()
            self._normalize_int_list(attributes, "members")
            self._normalize_optional_int(attributes, "interval")
            raw_sla = attributes.pop("sla", [])
            sla = []
            for entry in raw_sla:
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
            self.config.sdwan.health_checks.append(
                FGSDWanHealthCheck(**attributes)
            )

        elif section_path == "system sdwan service":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()
            if attributes.get("name") == str(attributes.get("id")):
                attributes["name"] = None
            self._normalize_int_list(attributes, "priority_members")
            self._normalize_int_list(attributes, "internet_service_app_ctrl")
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSDWanService.model_fields),
            )
            self.config.sdwan.services.append(FGSDWanService(**attributes))

        elif section_path == "firewall internet-service-name":
            # FortiOS source:
            #
            #   set internet-service-id 65536
            #
            # Generic parsing normalizes the key to:
            #
            #   internet_service_id
            #
            # FGInternetService uses the vendor-neutral source
            # identity field "id", so explicitly map it here.
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
                    # Preserve parser stability if FortiOS
                    # contains an unexpected ID representation.
                    attributes["id"] = None

            self.config.internet_services.append(
                FGInternetService(
                    **attributes
                )
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
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGLocalUser.model_fields),
            )
            self.config.local_users.append(FGLocalUser(**attributes))

        elif section_path == "user group":
            if "type" in attributes:
                attributes["group_type"] = attributes.pop("type")
            raw_matches = attributes.pop("match", [])
            matches = []
            for entry in raw_matches:
                if entry.get("name") == str(entry.get("id")):
                    entry.pop("name", None)
                matches.append(FGUserGroupMatch(**entry))
            attributes["match"] = matches
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

        elif section_path == "firewall DoS-policy":
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
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
            if attributes.get("name") == str(
                attributes.get("id")
            ):
                attributes["name"] = None

            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGSessionHelper.model_fields),
                )
            )

            self.config.session_helpers.append(
                FGSessionHelper(**attributes)
            )

        elif section_path == "system session-ttl port":
            if attributes.get("name") == str(
                attributes.get("id")
            ):
                attributes.pop("name", None)

            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(FGSessionTTLOverride.model_fields),
                )
            )

            self.config.session_ttl_overrides.append(
                FGSessionTTLOverride(**attributes)
            )

        elif section_path == "system dhcp server":
            # Numeric DHCP server edit IDs are initially stored as:
            #
            #   name = "1"
            #   id = 1
            #
            # DHCP servers use the numeric ID, not the synthetic name.
            if attributes.get("name") == str(
                attributes.get("id")
            ):
                attributes.pop("name", None)

            raw_ip_ranges = attributes.pop(
                "ip_ranges",
                [],
            )

            ip_ranges = []

            for range_attributes in raw_ip_ranges:
                if range_attributes.get("name") == str(
                    range_attributes.get("id")
                ):
                    range_attributes.pop(
                        "name",
                        None,
                    )

                range_attributes["extra_settings"] = (
                    _extract_extra_settings(
                        range_attributes,
                        set(
                            FGDHCPIPRange.model_fields
                        ),
                    )
                )

                ip_ranges.append(
                    FGDHCPIPRange(
                        **range_attributes
                    )
                )

            raw_reservations = attributes.pop(
                "reserved_addresses",
                [],
            )

            reserved_addresses = []

            for reservation_attributes in raw_reservations:
                if reservation_attributes.get(
                    "name"
                ) == str(
                    reservation_attributes.get(
                        "id"
                    )
                ):
                    reservation_attributes.pop(
                        "name",
                        None,
                    )

                reservation_attributes[
                    "extra_settings"
                ] = _extract_extra_settings(
                    reservation_attributes,
                    set(
                        FGDHCPReservation.model_fields
                    ),
                )

                reserved_addresses.append(
                    FGDHCPReservation(
                        **reservation_attributes
                    )
                )

            attributes["ip_ranges"] = ip_ranges
            attributes[
                "reserved_addresses"
            ] = reserved_addresses

            attributes["extra_settings"] = (
                _extract_extra_settings(
                    attributes,
                    set(
                        FGDHCPServer.model_fields
                    ),
                )
            )

            self.config.dhcp_servers.append(
                FGDHCPServer(
                    **attributes
                )
            )
            

def parse_fortigate_config(
    text: str,
) -> FGConfig:
    tokenizer = FortiGateTokenizer(text)
    parser = FortiGateParser(tokenizer)

    return parser.parse()
