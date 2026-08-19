import re
from typing import List, Dict, Optional, Any
from fg2pan.parsers.juniper_srx.model import (
    JuniperSRXConfig, JuniperAddress, JuniperAddressSet,
    JuniperApplication, JuniperApplicationSet, JuniperPolicy
)
from fg2pan.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRRoute
)
from fg2pan.ir.enums import AddressType, ServiceProtocol, PolicyAction

class JuniperSRXParser:
    """Parser for JunOS SRX firewall configurations in 'set' format."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = JuniperSRXConfig()

    def parse_raw(self) -> JuniperSRXConfig:
        policies_by_key: Dict[str, JuniperPolicy] = {}

        for line in self.raw_lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('/*'):
                continue

            # Hostname: set system host-name <name>
            m_host = re.match(r'^set\s+system\s+host-name\s+(\S+)', line, re.IGNORECASE)
            if m_host:
                self.config.hostname = m_host.group(1)
                continue

            # Zone interfaces: set security zones security-zone <zone> interfaces <intf>
            m_zone = re.match(r'^set\s+security\s+zones\s+security-zone\s+(\S+)\s+interfaces\s+(\S+)', line, re.IGNORECASE)
            if m_zone:
                z_name, intf = m_zone.group(1), m_zone.group(2)
                if z_name not in self.config.zones:
                    self.config.zones[z_name] = []
                if intf not in self.config.zones[z_name]:
                    self.config.zones[z_name].append(intf)
                continue

            # Global / Zone address: set security (zones security-zone <zone>|address-book global) address-book address <name> <val>
            m_addr_global = re.match(r'^set\s+security\s+address-book\s+global\s+address\s+(\S+)\s+(?:ip-prefix\s+|dns-name\s+|range-address\s+)?(\S+)', line, re.IGNORECASE)
            if m_addr_global:
                a_name, a_val = m_addr_global.group(1), m_addr_global.group(2)
                a_type = "dns-name" if 'dns-name' in line else "range" if 'range-address' in line else "ip-prefix"
                self.config.addresses.append(JuniperAddress(name=a_name, value=a_val, type=a_type))
                continue

            m_addr_zone = re.match(r'^set\s+security\s+zones\s+security-zone\s+(\S+)\s+address-book\s+address\s+(\S+)\s+(?:ip-prefix\s+|dns-name\s+|range-address\s+)?(\S+)', line, re.IGNORECASE)
            if m_addr_zone:
                z_name, a_name, a_val = m_addr_zone.group(1), m_addr_zone.group(2), m_addr_zone.group(3)
                a_type = "dns-name" if 'dns-name' in line else "range" if 'range-address' in line else "ip-prefix"
                self.config.addresses.append(JuniperAddress(name=a_name, zone=z_name, value=a_val, type=a_type))
                continue

            # Address-set: set security address-book global address-set <set_name> address <member>
            m_aset = re.match(r'^set\s+security\s+address-book\s+global\s+address-set\s+(\S+)\s+address\s+(\S+)', line, re.IGNORECASE)
            if m_aset:
                s_name, member = m_aset.group(1), m_aset.group(2)
                existing = next((s for s in self.config.address_sets if s.name == s_name), None)
                if not existing:
                    existing = JuniperAddressSet(name=s_name, members=[])
                    self.config.address_sets.append(existing)
                existing.members.append(member)
                continue

            # Application: set applications application <name> protocol <proto> destination-port <port>
            m_app = re.match(r'^set\s+applications\s+application\s+(\S+)\s+(.+)$', line, re.IGNORECASE)
            if m_app:
                app_name, app_tail = m_app.group(1), m_app.group(2)
                existing_app = next((a for a in self.config.applications if a.name == app_name), None)
                if not existing_app:
                    existing_app = JuniperApplication(name=app_name)
                    self.config.applications.append(existing_app)
                if 'protocol' in app_tail:
                    m_p = re.search(r'protocol\s+(\S+)', app_tail)
                    if m_p:
                        existing_app.protocol = m_p.group(1)
                if 'destination-port' in app_tail:
                    m_dp = re.search(r'destination-port\s+(\S+)', app_tail)
                    if m_dp:
                        existing_app.destination_port = m_dp.group(1)
                continue

            # Application-set: set applications application-set <name> application <member>
            m_appset = re.match(r'^set\s+applications\s+application-set\s+(\S+)\s+application\s+(\S+)', line, re.IGNORECASE)
            if m_appset:
                as_name, member = m_appset.group(1), m_appset.group(2)
                existing_as = next((s for s in self.config.application_sets if s.name == as_name), None)
                if not existing_as:
                    existing_as = JuniperApplicationSet(name=as_name, members=[])
                    self.config.application_sets.append(existing_as)
                existing_as.members.append(member)
                continue

            # Policies: set security policies from-zone <from> to-zone <to> policy <name> ...
            m_pol = re.match(r'^set\s+security\s+policies\s+from-zone\s+(\S+)\s+to-zone\s+(\S+)\s+policy\s+(\S+)\s+(.+)$', line, re.IGNORECASE)
            if m_pol:
                fz, tz, p_name, tail = m_pol.group(1), m_pol.group(2), m_pol.group(3), m_pol.group(4)
                pol_key = f"{fz}_{tz}_{p_name}"
                if pol_key not in policies_by_key:
                    policies_by_key[pol_key] = JuniperPolicy(name=p_name, from_zone=fz, to_zone=tz)

                p = policies_by_key[pol_key]
                if 'match source-address' in tail:
                    m_sa = re.search(r'source-address\s+(\S+)', tail)
                    if m_sa and m_sa.group(1) not in p.source_addresses:
                        p.source_addresses.append(m_sa.group(1))
                elif 'match destination-address' in tail:
                    m_da = re.search(r'destination-address\s+(\S+)', tail)
                    if m_da and m_da.group(1) not in p.destination_addresses:
                        p.destination_addresses.append(m_da.group(1))
                elif 'match application' in tail:
                    m_app_m = re.search(r'application\s+(\S+)', tail)
                    if m_app_m and m_app_m.group(1) not in p.applications:
                        p.applications.append(m_app_m.group(1))
                elif 'then permit' in tail:
                    p.action = "permit"
                elif 'then deny' in tail or 'then reject' in tail:
                    p.action = "deny"
                elif 'then count' in tail or 'then log' in tail:
                    p.log_session_close = True
                continue

            # Routes: set routing-options static route <dst> next-hop <gw>
            m_rt = re.match(r'^set\s+routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)', line, re.IGNORECASE)
            if m_rt:
                self.config.routes.append({"destination": m_rt.group(1), "next_hop": m_rt.group(2)})
                continue

        self.config.policies = list(policies_by_key.values())
        return self.config

    def transform_to_ir(self) -> IRConfig:
        cfg = self.parse_raw()
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="juniper_srx"))

        # Zones & Interfaces
        for z_name, intfs in cfg.zones.items():
            ir.zones.append(IRZone(name=z_name, interfaces=intfs))
            for intf in intfs:
                ir.interfaces.append(IRInterface(name=intf, zone=z_name))

        if not ir.zones:
            ir.zones.append(IRZone(name="trust", interfaces=["ge-0/0/0"]))
            ir.zones.append(IRZone(name="untrust", interfaces=["ge-0/0/1"]))

        # Addresses
        for a in cfg.addresses:
            a_type = AddressType.FQDN if a.type == "dns-name" else AddressType.RANGE if a.type == "range" else AddressType.NETWORK if '/' in a.value else AddressType.HOST
            val = a.value if '/' in a.value or a_type != AddressType.HOST else f"{a.value}/32"
            ir.addresses.append(IRAddress(name=a.name, type=a_type, value=val, description=a.description))

        # Address sets
        for s in cfg.address_sets:
            ir.address_groups.append(IRAddressGroup(name=s.name, members=s.members))

        # Applications -> Services
        for app in cfg.applications:
            proto = ServiceProtocol.TCP if app.protocol.lower() == 'tcp' else ServiceProtocol.UDP if app.protocol.lower() == 'udp' else ServiceProtocol.ICMP if app.protocol.lower() == 'icmp' else ServiceProtocol.IP
            port = app.destination_port or "any"
            ir.services.append(IRService(
                name=app.name,
                ports=[IRServicePort(protocol=proto, port=port)],
                description=app.description
            ))

        # Application sets -> Service Groups
        for aset in cfg.application_sets:
            ir.service_groups.append(IRServiceGroup(name=aset.name, members=aset.members))

        # Policies
        for p in cfg.policies:
            act = PolicyAction.ALLOW if p.action == 'permit' else PolicyAction.DENY
            ir.policies.append(IRPolicy(
                name=p.name,
                from_zone=[p.from_zone],
                to_zone=[p.to_zone],
                source=p.source_addresses if p.source_addresses else ["any"],
                destination=p.destination_addresses if p.destination_addresses else ["any"],
                service=p.applications if p.applications else ["any"],
                action=act,
                log_end=p.log_session_close,
                disabled=p.disabled
            ))

        # Routes
        for idx, r in enumerate(cfg.routes, 1):
            ir.routes.append(IRRoute(
                name=f"route_{idx}",
                destination=r["destination"],
                next_hop=r["next_hop"]
            ))

        return ir
