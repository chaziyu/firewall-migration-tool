"""Secure Connect graph assembled only from explicit source references."""

from .vpn import build_vpn_graph
from .interface_topology import build_interface_topology


def build_secure_connect_graph(context, scope: str, certificates=()) -> tuple[dict, ...]:
    edges = []
    topology = {row["name"]: row for row in build_interface_topology(context, scope)}
    for profile in context.remote_access.profiles.values():
        for target_type, relationship, reference, collection in (
            ("access-profile", "ACCESS_PROFILE", profile.access_profile, context.access_profiles),
            ("remote-access-client-config", "CLIENT_CONFIG", profile.client_config, context.remote_access.client_configs),
            ("ipsec-vpn", "IPSEC_VPN", profile.ipsec_vpn, context.vpn.ipsec_vpns),
        ):
            if reference:
                edges.append({"context": scope, "source_type": "remote-access-profile", "source_name": profile.name,
                              "relationship": relationship, "target_type": target_type, "target_name": reference,
                              "resolved": reference in collection})
        if profile.ipsec_vpn and profile.ipsec_vpn in context.vpn.ipsec_vpns:
            tunnel = context.vpn.ipsec_vpns[profile.ipsec_vpn]
            interface = tunnel.bind_interface
            if interface:
                zones = topology.get(interface, {}).get("zone_memberships", ())
                edges.append({"context": scope, "source_type": "ipsec-vpn", "source_name": tunnel.name,
                              "relationship": "TUNNEL_INTERFACE_ZONE", "target_type": "security-zone",
                              "target_name": zones, "resolved": bool(zones),
                              "interface": interface})
                for zone in dict.fromkeys(zones):
                    for policy in context.policies:
                        if zone in policy.from_zones or zone in policy.to_zones:
                            edges.append({"context": scope, "source_type": "security-zone", "source_name": zone,
                                          "relationship": "ZONE_ASSOCIATED_POLICY", "target_type": "security-policy",
                                          "target_name": policy.name, "resolved": True})
    edges.extend(edge for edge in build_vpn_graph(context, scope, certificates)
                 if edge["source_type"] in {"ipsec-vpn", "ike-gateway", "ike-policy", "ipsec-policy"})
    return tuple(edges)
