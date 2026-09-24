"""Explicit Junos IKE, IPsec, and tunnel-interface relationships."""

from ..resolver import JuniperReferenceResolver


def _edge(context, source_type, source_name, relationship, target_type, target_name, resolved,
          source_effective=True, **extra):
    return {"context": context, "source_type": source_type, "source_name": source_name,
            "relationship": relationship, "target_type": target_type, "target_name": target_name,
            "resolved": resolved, "source_effective": source_effective,
            "status": "INACTIVE_SOURCE" if not source_effective else
            "RESOLVED" if resolved else "UNRESOLVED", **extra}


def build_vpn_graph(context, scope: str, certificates=(), effective_lookup=None) -> tuple[dict, ...]:
    vpn = context.vpn
    resolver = JuniperReferenceResolver(context, effective_lookup)
    edges = []
    for gateway in vpn.ike_gateways.values():
        if gateway.ike_policy:
            edges.append(_edge(scope, "ike-gateway", gateway.name, "IKE_POLICY", "ike-policy", gateway.ike_policy,
                               resolver.resolve_ike_policy(gateway.ike_policy) is not None,
                               resolver.vpn_reference_is_effective("ike-gateway", gateway.name, "ike-policy", gateway.ike_policy)))
        if gateway.certificate_reference:
            edges.append(_edge(scope, "ike-gateway", gateway.name, "CERTIFICATE_REFERENCE", "certificate",
                               gateway.certificate_reference, gateway.certificate_reference in certificates))
    for policy in vpn.ike_policies.values():
        for proposal in policy.proposals:
            edges.append(_edge(scope, "ike-policy", policy.name, "IKE_PROPOSAL", "ike-proposal", proposal,
                               resolver.resolve_ike_proposal(proposal) is not None,
                               resolver.vpn_reference_is_effective("ike-policy", policy.name, "proposal", proposal)))
        for reference in (policy.certificate_reference, policy.local_certificate):
            if reference:
                edges.append(_edge(scope, "ike-policy", policy.name, "CERTIFICATE_REFERENCE", "certificate", reference,
                                   reference in certificates))
        if policy.proposal_set:
            edges.append(_edge(scope, "ike-policy", policy.name, "PROPOSAL_SET_UNEXPANDED", "proposal-set",
                               policy.proposal_set, None, status="SOURCE_ONLY"))
    for policy in vpn.ipsec_policies.values():
        for proposal in policy.proposals:
            edges.append(_edge(scope, "ipsec-policy", policy.name, "IPSEC_PROPOSAL", "ipsec-proposal", proposal,
                               resolver.resolve_ipsec_proposal(proposal) is not None,
                               resolver.vpn_reference_is_effective("ipsec-policy", policy.name, "proposal", proposal)))
        if policy.proposal_set:
            edges.append(_edge(scope, "ipsec-policy", policy.name, "PROPOSAL_SET_UNEXPANDED", "proposal-set",
                               policy.proposal_set, None, status="SOURCE_ONLY"))
    for tunnel in vpn.ipsec_vpns.values():
        if tunnel.ike_gateway:
            edges.append(_edge(scope, "ipsec-vpn", tunnel.name, "IKE_GATEWAY", "ike-gateway", tunnel.ike_gateway,
                               resolver.resolve_ike_gateway(tunnel.ike_gateway) is not None,
                               resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "ike-gateway", tunnel.ike_gateway)))
        if tunnel.ipsec_policy:
            edges.append(_edge(scope, "ipsec-vpn", tunnel.name, "IPSEC_POLICY", "ipsec-policy", tunnel.ipsec_policy,
                               resolver.resolve_ipsec_policy(tunnel.ipsec_policy) is not None,
                               resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "ipsec-policy", tunnel.ipsec_policy)))
        if tunnel.bind_interface:
            edges.append(_edge(scope, "ipsec-vpn", tunnel.name, "BIND_INTERFACE", "interface", tunnel.bind_interface,
                               resolver.resolve_interface(tunnel.bind_interface) is not None,
                               resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "bind-interface", tunnel.bind_interface)))
        monitor = tunnel.vpn_monitor
        if monitor and monitor.source_interface:
            edges.append(_edge(scope, "vpn-monitor", tunnel.name, "SOURCE_INTERFACE", "interface", monitor.source_interface,
                               resolver.resolve_interface(monitor.source_interface) is not None,
                               resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "source-interface", monitor.source_interface)))
    return tuple(edges)
