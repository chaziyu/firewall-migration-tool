"""Temporary report projections retained for existing Juniper consumers."""

from .interface_topology import build_interface_topology
from .policies import build_policy_relationships


def build_compatibility_views(config, effective_lookup=None):
    views = {key: [] for key in ("interface_topology", "zone_memberships", "routing_instances", "address_books",
                                  "applications", "policies", "nat_rule_sets", "vpn_relationships", "dhcp",
                                  "access_profiles", "firewall_users", "apbr", "remote_access")}
    for context in config.iter_contexts():
        scope = context.name if context.context_type == "root" else f"{context.context_type} {context.name}"
        views["interface_topology"].extend(build_interface_topology(context, scope))
        for zone in context.zones.values():
            views["zone_memberships"].extend({"context": scope, "zone": zone.name, "interface": interface}
                                              for interface in zone.interfaces)
        views["routing_instances"].extend({"context": scope, "name": name, "interfaces": list(item.interfaces)}
                                           for name, item in context.routing_instances.items())
        views["address_books"].extend({"context": scope, "name": name, "zones": list(book.attached_zones),
                                       "addresses": list(book.addresses), "address_sets": list(book.address_sets)}
                                      for name, book in context.address_books.items())
        views["applications"].extend({"context": scope, "name": name, "terms": list(getattr(item, "terms", []))}
                                     for name, item in context.applications.items())
        policy_view = build_policy_relationships(context, scope, effective_lookup)
        views["policies"].extend(row for group in policy_view["zone_policy_sets"] for row in group["policies"])
        views["policies"].extend(policy_view["global_policies"])
        for kind, sets in (("source", context.nat.source_rule_sets), ("destination", context.nat.destination_rule_sets),
                           ("static", context.nat.static_rule_sets)):
            views["nat_rule_sets"].extend({"context": scope, "type": kind, "name": name,
                                           "rules": [rule.name for rule in rule_set.rules]}
                                          for name, rule_set in sets.items())
        views["vpn_relationships"].extend({"context": scope, "name": name, "type": kind}
                                          for kind, items in (("ike-proposal", context.vpn.ike_proposals),
                                                              ("ike-policy", context.vpn.ike_policies),
                                                              ("ike-gateway", context.vpn.ike_gateways),
                                                              ("ipsec-vpn", context.vpn.ipsec_vpns))
                                          for name in items)
        for group in context.dhcp.local_servers.values():
            views["dhcp"].extend({"context": scope, "kind": "local-server", "name": group.name,
                                  "routing_instance": group.routing_instance, "family": group.family,
                                  "interface": interface} for interface in group.interfaces or [None])
        for group in context.dhcp.relay_groups.values():
            views["dhcp"].append({"context": scope, "kind": "relay-group", "name": group.name,
                                  "routing_instance": group.routing_instance,
                                  "interfaces": list(group.interfaces), "server_groups": list(group.server_groups)})
        for pool in context.dhcp.address_assignment_pools.values():
            for family_name, family in pool.families.items():
                views["dhcp"].append({"context": scope, "kind": "address-assignment-pool", "name": pool.name,
                                      "routing_instance": pool.routing_instance, "family": family_name,
                                      "linked_pool": pool.linked_pool,
                                      "ranges": [{"name": row.name, "low": row.low, "high": row.high} for row in family.ranges.values()],
                                      "hosts": [{"name": row.name, "hardware_address": row.hardware_address, "ip_address": row.ip_address}
                                                for row in family.hosts.values()],
                                      "router": list(family.dhcp_attributes.router),
                                      "name_servers": list(family.dhcp_attributes.name_servers)})
        for profile in context.access_profiles.values():
            views["access_profiles"].append({"context": scope, "name": profile.name, "clients": list(profile.clients)})
            for client in profile.clients.values():
                if client.firewall_user:
                    views["firewall_users"].append({"context": scope, "access_profile": profile.name,
                                                     "name": client.name,
                                                     "password_configured": client.firewall_user.password_configured,
                                                     "client_groups": list(client.client_groups)})
        for kind, items in (("metrics-profile", context.apbr.metrics_profiles),
                            ("active-probe-params", context.apbr.active_probe_params),
                            ("passive-probe-params", context.apbr.passive_probe_params),
                            ("overlay-path", context.apbr.overlay_paths),
                            ("destination-path-group", context.apbr.destination_path_groups),
                            ("multipath-rule", context.apbr.multipath_rules), ("sla-rule", context.apbr.sla_rules)):
            views["apbr"].extend({"context": scope, "kind": kind, "name": name} for name in items)
        for profile in context.remote_access.profiles.values():
            views["remote_access"].append({"context": scope, "kind": "profile", "name": profile.name,
                                           "access_profile": profile.access_profile, "client_config": profile.client_config,
                                           "ipsec_vpn": profile.ipsec_vpn, "multi_access": profile.multi_access})
        for item in context.remote_access.client_configs.values():
            views["remote_access"].append({"context": scope, "kind": "client-config", "name": item.name,
                                           "application_bypass_terms": list(item.application_bypass_terms)})
    return {key: tuple(value) for key, value in views.items()}
