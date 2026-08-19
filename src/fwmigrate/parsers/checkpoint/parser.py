import json
from typing import Dict, Any, List, Optional
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRNATRule
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

class CheckPointParser:
    """Parser for Check Point R80/R81 JSON database dumps and API exports."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_content = content
        self.zone_mapping = zone_mapping or {}

    def parse(self) -> IRConfig:
        try:
            data = json.loads(self.raw_content)
        except Exception:
            data = {}

        ir = IRConfig(metadata=IRMetadata(
            hostname=data.get('name', 'checkpoint-gw'),
            source_vendor="checkpoint"
        ))

        # Default zones
        ir.zones.append(IRZone(name="trust", interfaces=["eth0"]))
        ir.zones.append(IRZone(name="untrust", interfaces=["eth1"]))
        ir.interfaces.append(IRInterface(name="eth0", zone="trust"))
        ir.interfaces.append(IRInterface(name="eth1", zone="untrust"))

        # Check for 'objects' list or dictionary of objects
        objects = data.get('objects', [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj in objects:
            obj_type = obj.get('type', '')
            name = obj.get('name', '')
            comments = obj.get('comments')

            if obj_type == 'host':
                ip = obj.get('ipv4-address') or obj.get('ipv4_address') or '0.0.0.0'
                ir.addresses.append(IRAddress(
                    name=name, type=AddressType.HOST, value=f"{ip}/32", description=comments
                ))
            elif obj_type == 'network':
                subnet = obj.get('subnet4') or obj.get('subnet') or '0.0.0.0'
                mask_len = obj.get('mask-length4') or obj.get('mask_length4') or 24
                ir.addresses.append(IRAddress(
                    name=name, type=AddressType.NETWORK, value=f"{subnet}/{mask_len}", description=comments
                ))
            elif obj_type == 'address-range':
                ip_first = obj.get('ipv4-address-first') or obj.get('ipv4_address_first') or '0.0.0.0'
                ip_last = obj.get('ipv4-address-last') or obj.get('ipv4_address_last') or '0.0.0.0'
                ir.addresses.append(IRAddress(
                    name=name, type=AddressType.RANGE, value=f"{ip_first}-{ip_last}", description=comments
                ))
            elif obj_type == 'group':
                members = [m.get('name', str(m)) if isinstance(m, dict) else str(m) for m in obj.get('members', [])]
                ir.address_groups.append(IRAddressGroup(
                    name=name, members=members, description=comments
                ))
            elif obj_type in ['service-tcp', 'service-udp']:
                proto = ServiceProtocol.TCP if obj_type == 'service-tcp' else ServiceProtocol.UDP
                port = str(obj.get('port', 'any'))
                ir.services.append(IRService(
                    name=name,
                    ports=[IRServicePort(protocol=proto, port=port)],
                    description=comments
                ))
            elif obj_type == 'service-group':
                members = [m.get('name', str(m)) if isinstance(m, dict) else str(m) for m in obj.get('members', [])]
                ir.service_groups.append(IRServiceGroup(
                    name=name, members=members, description=comments
                ))

        # Check for 'rulebase' or 'access-rulebase'
        rulebase = data.get('rulebase') or data.get('access-rulebase') or data.get('rules') or []
        for idx, rule in enumerate(rulebase, 1):
            rule_name = rule.get('name') or f"Rule_{rule.get('rule-number', idx)}"
            action_raw = str(rule.get('action', 'Accept')).lower()
            action = PolicyAction.ALLOW if 'accept' in action_raw else PolicyAction.DENY

            sources = [s.get('name', str(s)) if isinstance(s, dict) else str(s) for s in rule.get('source', [])]
            destinations = [d.get('name', str(d)) if isinstance(d, dict) else str(d) for d in rule.get('destination', [])]
            services = [svc.get('name', str(svc)) if isinstance(svc, dict) else str(svc) for svc in rule.get('service', [])]

            ir.policies.append(IRPolicy(
                name=rule_name,
                from_zone=["any"],
                to_zone=["any"],
                source=sources if sources else ["any"],
                destination=destinations if destinations else ["any"],
                service=services if services else ["any"],
                action=action,
                description=rule.get('comments'),
                disabled=not rule.get('enabled', True)
            ))

        # Check for 'nat-rulebase'
        nat_rulebase = data.get('nat-rulebase') or data.get('nat_rules') or []
        for idx, nrule in enumerate(nat_rulebase, 1):
            n_name = nrule.get('name') or f"NAT_Rule_{idx}"
            ir.nat_rules.append(IRNATRule(
                name=n_name,
                type=NATType.SOURCE,
                from_zone=["any"],
                to_zone=["any"],
                source=["any"],
                destination=["any"],
                translated_source=nrule.get('translated-source', {}).get('name') if isinstance(nrule.get('translated-source'), dict) else None
            ))

        return ir
