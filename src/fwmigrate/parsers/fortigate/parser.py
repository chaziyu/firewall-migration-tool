from typing import Iterator, List, Dict, Any, Optional
from fwmigrate.parsers.fortigate.tokenizer import Token, TokenType, FortiGateTokenizer
from fwmigrate.parsers.fortigate.model import (
    FGConfig, FGSystemGlobal, FGInterface, FGSystemZone, FGAddress, FGAddressGroup,
    FGWildcardFQDN, FGService, FGServiceGroup, FGSchedule, FGIPPool,
    FGVIP, FGVIPGroup, FGPolicy, FGPhase1Interface, FGPhase2Interface,
    FGStaticRoute, FGSDWan, FGDns, FGSDWanZone, FGSDWanMember
)
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.blocks import read_blocks
from fwmigrate.extraction.models import SourceObjectResult, SourceSectionResult, ExtractionStatus
from fwmigrate.parsers.fortigate.model import FGCentralSNAT
from pydantic import ValidationError
import re

NAT_SECTIONS = {"firewall ippool", "firewall vip", "firewall vipgrp", "firewall policy", "firewall central-snat-map", "system settings"}

def is_nat_section(path):
    return path in NAT_SECTIONS or any(path.startswith(prefix) for prefix in (
        "firewall vip", "firewall ippool", "firewall central-snat", "firewall policy6", "firewall policy64", "firewall policy46"))

class ParserError(Exception):
    pass

class FortiGateParser:
    def __init__(self, tokenizer: FortiGateTokenizer):
        self.text = tokenizer.text.lstrip('\ufeff')
        self.tokens = list(tokenizer.tokenize())
        self.pos = 0
        self.config = FGConfig()
        
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
            raise ParserError(f"Expected {expected_type}, but reached end of file")
        if token.type != expected_type:
            raise ParserError(f"Expected {expected_type} at line {token.line_number}, got {token.type} ({token.value})")
        return token

    def parse(self) -> FGConfig:
        tree = read_blocks(self.text)
        if not tree.children:
            raise ParserError("No FortiGate configuration blocks found; cannot verify source extraction.")
        version = re.search(r"#config-version=.*?-(\d+\.\d+\.\d+)", self.text)
        self.config.source_version = version.group(1) if version else None
        self.config.scopes = list(dict.fromkeys(
            item.name for node in tree.children if node.kind == "config" and node.name == "vdom"
            for item in node.children if item.kind == "edit"
        )) or ["root"]
        if tree.all_errors():
            self.config.extraction.blocking_issues.extend(tree.all_errors())
        if len(self.config.scopes) > 1:
            self.config.extraction.blocking_issues.append("Multiple VDOMs are retained for inventory only. Supply one VDOM per input for canonical normalization.")
        self._walk_blocks(tree, "", "root")
        # Repeated section blocks belong to the same source inventory domain.
        combined = {}
        for section in self.config.extraction.sections:
            key = (section.path, section.scope)
            if key in combined:
                combined[key].source_count += section.source_count
                combined[key].notes.extend(section.notes)
            else:
                combined[key] = section
        self.config.extraction.sections = list(combined.values())
        return self.config

    def _walk_blocks(self, parent, prefix, scope):
        for block in parent.children:
            if block.kind != "config":
                continue
            if block.name == "vdom" and not prefix:
                for vdom in block.children:
                    if vdom.kind == "edit":
                        self._walk_blocks(vdom, "", vdom.name)
                continue
            if block.name == "global" and not prefix:
                self._walk_blocks(block, "", "global")
                continue
            path = f"{prefix} {block.name}".strip()
            tracked = is_nat_section(path)
            edits = [b for b in block.children if b.kind == "edit"]
            if tracked:
                self.config.extraction.sections.append(SourceSectionResult(
                    path=path, scope=scope, source_count=len(edits) + int(bool(block.settings or block.commands or (block.errors and not edits))),
                    notes=block.errors,
                ))
            if block.settings or (tracked and (block.commands or (block.errors and not edits))):
                attrs = {}
                for key, values in block.settings.items():
                    self.apply_attribute(attrs, key.replace("_", "-"), values, path)
                    self.apply_global_set(path, key.replace("_", "-"), values)
                if path == "system settings":
                    self.config.settings_by_scope[scope] = attrs
                if tracked:
                    self._record_block(path, scope, block, attrs, 0)
            for sequence, item in enumerate(edits, 1):
                attrs = {"name": item.name}
                if item.name.isdigit():
                    attrs["id"] = int(item.name)
                for key, values in item.settings.items():
                    self.apply_attribute(attrs, key.replace("_", "-"), values, path)
                record = self._record_block(path, scope, item, attrs, sequence) if tracked else None
                if record:
                    attrs["source_record"] = record
                # Flat legacy object collections cannot safely resolve cross-VDOM names.
                if len(self.config.scopes) > 1 and scope != "global":
                    if record:
                        record.status = ExtractionStatus.UNSUPPORTED
                        record.blocking = True
                        record.notes.append("Multiple VDOMs preserved separately in inventory; canonical migration requires one VDOM per input.")
                    continue
                if record and not record.parsed:
                    continue
                try:
                    self.build_model(path, attrs)
                except (ValidationError, ValueError) as error:
                    if not record:
                        raise
                    record.status = ExtractionStatus.PARSE_ERROR
                    record.parsed = False
                    record.blocking = True
                    # Pydantic's default text includes input values; never log those.
                    fields = [".".join(map(str, e["loc"])) for e in error.errors()] if isinstance(error, ValidationError) else []
                    record.notes.append("Invalid or missing fields: " + ", ".join(fields))
                if not tracked:
                    self._walk_blocks(item, path, scope)
            if not tracked:
                self._walk_blocks(block, path, scope)

    def _record_block(self, path, scope, block, attrs, sequence):
        errors = block.all_errors()
        sequence = 1 + sum(o.section == path and o.scope == scope for o in self.config.extraction.objects)
        record = SourceObjectResult(
            id=f"{scope}:{path}:{block.name}:{block.line_start}", section=path,
            name=block.name, scope=scope, sequence=sequence,
            line_start=block.line_start, line_end=block.line_end,
            attributes=sanitize_source_attributes(block.inventory()),
            parsed=not errors, notes=errors,
            status=ExtractionStatus.PARSE_ERROR if errors else ExtractionStatus.EXTRACT_ONLY,
            blocking=bool(errors),
        )
        if path not in NAT_SECTIONS:
            record.status = ExtractionStatus.UNSUPPORTED
            record.blocking = True
            record.notes.append("NAT variant retained for inventory; canonical normalization is not implemented.")
        self.config.extraction.objects.append(record)
        return record

    def parse_config_block(self, parent_path: str):
        section_parts = []
        while self.peek() and self.peek().type == TokenType.STRING:
            section_parts.append(self.next_token().value)
            
        if not section_parts:
            return
            
        current_path = " ".join(section_parts)
        full_path = f"{parent_path} {current_path}".strip()
        
        while self.peek():
            token = self.peek()
            if token.type == TokenType.END:
                self.consume(TokenType.END)
                break
            elif token.type == TokenType.EDIT:
                self.parse_edit_block(full_path)
            elif token.type == TokenType.SET:
                key, values = self.parse_set()
                self.apply_global_set(full_path, key, values)
            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)
                self.parse_config_block(full_path)
            else:
                self.next_token()

    def parse_edit_block(self, section_path: str):
        self.consume(TokenType.EDIT)
        name_token = self.consume(TokenType.STRING)
        item_name = name_token.value
        
        attributes = {"name": item_name}
        if item_name.isdigit():
            attributes["id"] = int(item_name)
            
        while self.peek():
            token = self.peek()
            if token.type in (TokenType.NEXT, TokenType.END):
                if token.type == TokenType.NEXT:
                    self.consume(TokenType.NEXT)
                break
            elif token.type == TokenType.SET:
                key, values = self.parse_set()
                self.apply_attribute(attributes, key, values, section_path)
            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)
                self.parse_config_block(section_path)
            else:
                self.next_token()

        self.build_model(section_path, attributes)

    def parse_set(self) -> tuple[str, List[str]]:
        self.consume(TokenType.SET)
        key_token = self.consume(TokenType.STRING)
        key = key_token.value
        
        values = []
        current_line = key_token.line_number
        while self.peek() and self.peek().type == TokenType.STRING and self.peek().line_number == current_line:
            values.append(self.next_token().value)
            
        return key, values

    def apply_attribute(self, attributes: Dict[str, Any], key: str, values: List[str], section_path: str = ""):
        clean_key = key.replace("-", "_")
        
        list_fields = {"allowaccess", "member", "day", "srcintf", "dstintf", 
                       "srcaddr", "dstaddr", "service", "poolname", "proposal", "internet_service_name",
                       "orig_addr", "dst_addr", "nat_ippool", "src_filter", "srcintf_filter"}
                       
        if clean_key in list_fields or (clean_key == "interface" and section_path == "system zone"):
            attributes[clean_key] = values
        elif len(values) == 0:
            attributes[clean_key] = True
        elif len(values) == 1:
            attributes[clean_key] = values[0]
        else:
            if key == "subnet" or key == "ip":
                attributes[clean_key] = f"{values[0]} {values[1]}"
            elif key in ["tcp-portrange", "udp-portrange"]:
                attributes[clean_key] = ",".join(values)
            else:
                attributes[clean_key] = " ".join(values)

    def apply_global_set(self, section_path: str, key: str, values: List[str]):
        if section_path == "system global":
            if not self.config.system_global:
                self.config.system_global = FGSystemGlobal(hostname="unknown")
            if key == "hostname" and values:
                self.config.system_global.hostname = values[0]
            elif key == "admin-sport" and values:
                self.config.system_global.admin_sport = int(values[0])
        elif section_path == "system sdwan":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()
            if key == "status" and values:
                self.config.sdwan.status = values[0]

    def build_model(self, section_path: str, attributes: Dict[str, Any]):
        if section_path == "system zone":
            self.config.system_zones.append(FGSystemZone(**attributes))
        elif section_path == "system interface":
            explicit_settings = {
                key: value for key, value in attributes.items()
                if key not in {"name", "id"}
            }
            attributes["source_attributes"] = sanitize_source_attributes(explicit_settings)
            self.config.interfaces.append(FGInterface(**attributes))
        elif section_path == "firewall address":
            self.config.addresses.append(FGAddress(**attributes))
        elif section_path == "firewall address6":
            attributes["is_ipv6"] = True
            self.config.addresses.append(FGAddress(**attributes))
        elif section_path == "firewall multicast-address":
            attributes["is_multicast"] = True
            self.config.addresses.append(FGAddress(**attributes))
        elif section_path == "firewall addrgrp":
            self.config.address_groups.append(FGAddressGroup(**attributes))
        elif section_path == "firewall wildcard-fqdn custom":
            self.config.wildcard_fqdns.append(FGWildcardFQDN(**attributes))
        elif section_path == "firewall service custom":
            self.config.services.append(FGService(**attributes))
        elif section_path == "firewall service group":
            self.config.service_groups.append(FGServiceGroup(**attributes))
        elif section_path == "firewall schedule recurring":
            self.config.schedules.append(FGSchedule(**attributes))
        elif section_path == "firewall ippool":
            self.config.ip_pools.append(FGIPPool(**attributes))
        elif section_path == "firewall vip":
            self.config.vips.append(FGVIP(**attributes))
        elif section_path == "firewall vipgrp":
            self.config.vip_groups.append(FGVIPGroup(**attributes))
        elif section_path == "firewall policy":
            self.config.policies.append(FGPolicy(**attributes))
        elif section_path == "firewall central-snat-map":
            self.config.central_snat.append(FGCentralSNAT(**attributes))
        elif section_path == "vpn ipsec phase1-interface":
            self.config.phase1_interfaces.append(FGPhase1Interface(**attributes))
        elif section_path == "vpn ipsec phase2-interface":
            self.config.phase2_interfaces.append(FGPhase2Interface(**attributes))
        elif section_path == "router static":
            self.config.static_routes.append(FGStaticRoute(**attributes))
        elif section_path == "system sdwan zone":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()
            self.config.sdwan.zones.append(FGSDWanZone(**attributes))
        elif section_path == "system sdwan members":
            if not self.config.sdwan:
                self.config.sdwan = FGSDWan()
            self.config.sdwan.members.append(FGSDWanMember(**attributes))
        elif section_path == "firewall internet-service-name":
            from fwmigrate.parsers.fortigate.model import FGInternetService
            self.config.internet_services.append(FGInternetService(**attributes))

def parse_fortigate_config(text: str) -> FGConfig:
    tokenizer = FortiGateTokenizer(text)
    parser = FortiGateParser(tokenizer)
    return parser.parse()
