from typing import Iterator, List, Dict, Any, Optional
from fwmigrate.parsers.fortigate.tokenizer import Token, TokenType, FortiGateTokenizer
from fwmigrate.parsers.fortigate.model import (
    FGConfig, FGSystemGlobal, FGInterface, FGSystemZone, FGAddress, FGAddressGroup,
    FGWildcardFQDN, FGService, FGServiceGroup, FGSchedule, FGIPPool,
    FGVIP, FGVIPGroup, FGPolicy, FGPhase1Interface, FGPhase2Interface,
    FGStaticRoute, FGSDWan, FGDns, FGSDWanZone, FGSDWanMember
)

class ParserError(Exception):
    pass

class FortiGateParser:
    def __init__(self, tokenizer: FortiGateTokenizer):
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
        while self.peek():
            token = self.next_token()
            if token.type == TokenType.COMMENT:
                continue
            elif token.type == TokenType.CONFIG:
                self.parse_config_block("")
            else:
                pass
        return self.config

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
                       "srcaddr", "dstaddr", "service", "poolname", "proposal", "internet_service_name"}
                       
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
