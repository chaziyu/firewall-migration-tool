"""Native PAN objects to bounded Cisco FMC REST API creation requests."""

from ipaddress import IPv4Address, IPv4Network
import re

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

from ..models import FTDPlanItem
from .naming import target_name
from .source_scope import identity, in_scope


def operation(key, path, body, value_type="object_id"):
    return ("fmc_operation", {
        "path": path,
        "request_body_template": body,
        "response_binding": {
            "binding_id": key + ".id",
            "json_pointer": "/id",
            "value_type": value_type,
        },
    })


def item(obj, family, *, settings=(), dependencies=(), blockers=(), suffix="", name=None, order=None):
    scope = pan_scope_identity(obj.scope) if obj.scope else "unscoped"
    raw_name = obj.name or "(unnamed)"
    tgt_name = name or target_name(family, scope, raw_name + suffix)
    return FTDPlanItem(
        identity(obj, family) + suffix,
        family,
        scope,
        raw_name,
        tgt_name,
        tuple(settings),
        tuple(dict.fromkeys(dependencies)),
        tuple(dict.fromkeys(blockers)),
        (obj.source_order or 0) if order is None else order,
        source_path=obj.source_path,
        source_kind=type(obj).__name__,
    )


def binding(key, fmc_type):
    return {"id": {"$response_binding": key + ".id"}, "type": fmc_type}


def _ports(value):
    if not isinstance(value, str):
        raise ValueError("SERVICE_PORTS_MUST_BE_EXPLICIT")
    result = []
    for token in value.split(","):
        parts = token.strip().split("-")
        if len(parts) not in {1, 2} or any(not part.isdecimal() for part in parts):
            raise ValueError("SERVICE_PORTS_INVALID")
        low, high = int(parts[0]), int(parts[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError("SERVICE_PORTS_INVALID")
        result.append(str(low) if low == high else f"{low}-{high}")
    return tuple(dict.fromkeys(result))


def plan_addresses(source, selected, domain_id):
    result, refs = [], {}
    for obj in (obj for obj in source.addresses if in_scope(obj, selected)):
        row = item(obj, "address")
        blockers, path, body, fmc_type = [], None, {}, "Network"
        if (
            obj.raw_extra or obj.fqdn or obj.ip_wildcard
            or len(obj.explicit_fields & {"ip_netmask", "ip_range", "fqdn", "ip_wildcard"}) != 1
        ):
            blockers.append("ADDRESS_REPRESENTATION_UNSUPPORTED")
        try:
            if obj.ip_netmask:
                prefix = IPv4Network(obj.ip_netmask, strict=False)
                if prefix.prefixlen == 32:
                    path = f"/api/fmc_config/v1/domain/{domain_id}/object/hosts"
                    body = {"name": row.target_name, "value": str(prefix.network_address), "type": "Host"}
                    fmc_type = "Host"
                else:
                    path = f"/api/fmc_config/v1/domain/{domain_id}/object/networks"
                    body = {"name": row.target_name, "value": str(prefix), "type": "Network"}
                    fmc_type = "Network"
            elif obj.ip_range:
                low, high = (IPv4Address(value.strip()) for value in obj.ip_range.split("-", 1))
                if low > high:
                    raise ValueError
                path = f"/api/fmc_config/v1/domain/{domain_id}/object/ranges"
                body = {"name": row.target_name, "value": f"{low}-{high}", "type": "Range"}
                fmc_type = "Range"
            else:
                raise ValueError
        except (ValueError, TypeError):
            blockers.append("ADDRESS_VALUE_UNSUPPORTED")

        settings = (
            (operation(row.key, path, body, fmc_type), ("fmc_type", fmc_type))
            if path else ()
        )
        row = item(obj, "address", blockers=blockers, settings=settings)
        result.append(row)
        refs.setdefault(obj.name, []).append(row)

    # Address groups
    for obj in (obj for obj in source.address_groups if in_scope(obj, selected)):
        members = obj.static_members
        deps, blockers, member_bindings = [], [], []
        if obj.raw_extra or not members or getattr(obj, "dynamic_filter", None):
            blockers.append("GROUP_MEMBERSHIP_MUST_BE_STATIC_AND_EXPLICIT")
        for name in members or ():
            matches = refs.get(name, ())
            if len(matches) != 1:
                blockers.append("GROUP_MEMBER_UNRESOLVED_OR_AMBIGUOUS")
            else:
                dep_item = matches[0]
                deps.append(dep_item.key)
                dep_type = dict(dep_item.settings).get("fmc_type", "Network")
                member_bindings.append(binding(dep_item.key, dep_type))

        row = item(obj, "address_group", dependencies=deps, blockers=blockers)
        path = f"/api/fmc_config/v1/domain/{domain_id}/object/networkgroups"
        body = {"name": row.target_name, "objects": member_bindings, "type": "NetworkGroup"}
        settings = (operation(row.key, path, body, "NetworkGroup"), ("fmc_type", "NetworkGroup"))
        row = item(obj, "address_group", dependencies=deps, blockers=blockers, settings=settings)
        result.append(row)
        refs.setdefault(obj.name, []).append(row)

    return result


def plan_services(source, selected, domain_id):
    result, refs = [], {}
    for obj in (obj for obj in source.services if in_scope(obj, selected)):
        blockers = []
        try:
            if obj.raw_extra or (obj.tcp is None) == (obj.udp is None):
                raise ValueError("SERVICE_PROTOCOL_OR_SETTINGS_UNSUPPORTED")
            branch = obj.tcp or obj.udp
            if branch.raw_extra or branch.override:
                raise ValueError("SERVICE_OVERRIDE_OR_UNKNOWN_SETTINGS_UNSUPPORTED")
            protocol = "TCP" if obj.tcp else "UDP"
            destinations = _ports(branch.port)
            sources = _ports(branch.source_port) if branch.source_port else ()
            if len(destinations) > 128:
                raise ValueError("SERVICE_EXPANSION_LIMIT")
        except ValueError as exc:
            blockers.append(str(exc))
            row = item(obj, "service", blockers=blockers)
            result.append(row)
            refs.setdefault(obj.name, []).append(row)
            continue

        # Create source port object if source-port is constrained (not ephemeral/any)
        src_port_item = None
        if sources and sources != ("1-65535",) and sources != ("0-65535",):
            src_name = f"{obj.name}_src"
            src_leaf = item(obj, "service", suffix="_src", name=src_name)
            src_path = f"/api/fmc_config/v1/domain/{domain_id}/object/protocolportobjects"
            src_port_val = ",".join(sources)
            src_body = {"name": src_leaf.target_name, "protocol": protocol, "port": src_port_val, "type": "ProtocolPortObject"}
            src_port_item = item(obj, "service", suffix="_src", name=src_name,
                                 settings=(operation(src_leaf.key, src_path, src_body, "ProtocolPortObject"),
                                           ("fmc_type", "ProtocolPortObject"), ("is_source_port", True)))
            result.append(src_port_item)

        # If single destination port token and no multi-leaf needed
        if len(destinations) == 1:
            row = item(obj, "service")
            path = f"/api/fmc_config/v1/domain/{domain_id}/object/protocolportobjects"
            body = {"name": row.target_name, "protocol": protocol, "port": destinations[0], "type": "ProtocolPortObject"}
            settings = [operation(row.key, path, body, "ProtocolPortObject"), ("fmc_type", "ProtocolPortObject")]
            deps = []
            if src_port_item:
                settings.append(("source_port_key", src_port_item.key))
                deps.append(src_port_item.key)
            row = item(obj, "service", dependencies=deps, blockers=blockers, settings=tuple(settings))
            result.append(row)
            refs.setdefault(obj.name, []).append(row)
        else:
            # Multi-port destination: create ProtocolPortObject leaves and group them in PortObjectGroup
            leaves = []
            for idx, dst_port in enumerate(destinations):
                leaf_suffix = f"_{idx}"
                leaf_name = f"{obj.name}_{re.sub(r'[^A-Za-z0-9]', '_', dst_port)}"
                leaf = item(obj, "service", suffix=leaf_suffix, name=leaf_name)
                path = f"/api/fmc_config/v1/domain/{domain_id}/object/protocolportobjects"
                body = {"name": leaf.target_name, "protocol": protocol, "port": dst_port, "type": "ProtocolPortObject"}
                leaf = item(obj, "service", suffix=leaf_suffix, name=leaf_name,
                            settings=(operation(leaf.key, path, body, "ProtocolPortObject"), ("fmc_type", "ProtocolPortObject")))
                leaves.append(leaf)
            result.extend(leaves)

            deps = [leaf.key for leaf in leaves]
            member_bindings = [binding(leaf.key, "ProtocolPortObject") for leaf in leaves]
            row = item(obj, "service_group")
            path = f"/api/fmc_config/v1/domain/{domain_id}/object/portobjectgroups"
            body = {"name": row.target_name, "objects": member_bindings, "type": "PortObjectGroup"}
            settings = [operation(row.key, path, body, "PortObjectGroup"), ("fmc_type", "PortObjectGroup")]
            if src_port_item:
                settings.append(("source_port_key", src_port_item.key))
                deps.append(src_port_item.key)
            row = item(obj, "service_group", dependencies=deps, blockers=blockers, settings=tuple(settings))
            result.append(row)
            refs.setdefault(obj.name, []).append(row)

    # Service groups from source
    for obj in (obj for obj in source.service_groups if in_scope(obj, selected)):
        members = obj.members
        deps, blockers, member_bindings = [], [], []
        if obj.raw_extra or not members:
            blockers.append("GROUP_MEMBERSHIP_MUST_BE_STATIC_AND_EXPLICIT")
        for name in members or ():
            matches = refs.get(name, ())
            if len(matches) != 1:
                blockers.append("GROUP_MEMBER_UNRESOLVED_OR_AMBIGUOUS")
            else:
                dep_item = matches[0]
                deps.append(dep_item.key)
                dep_type = dict(dep_item.settings).get("fmc_type", "ProtocolPortObject")
                member_bindings.append(binding(dep_item.key, dep_type))

        row = item(obj, "service_group", dependencies=deps, blockers=blockers)
        path = f"/api/fmc_config/v1/domain/{domain_id}/object/portobjectgroups"
        body = {"name": row.target_name, "objects": member_bindings, "type": "PortObjectGroup"}
        settings = (operation(row.key, path, body, "PortObjectGroup"), ("fmc_type", "PortObjectGroup"))
        row = item(obj, "service_group", dependencies=deps, blockers=blockers, settings=settings)
        result.append(row)
        refs.setdefault(obj.name, []).append(row)

    return result


def plan_zones(source, selected, domain_id):
    result = []
    for obj in (obj for obj in source.zones if in_scope(obj, selected)):
        row = item(obj, "zone")
        blockers = []
        extra = obj.model_dump(exclude={
            "name", "source_path", "scope", "source_order", "explicit_fields",
            "raw_extra", "network_type", "members", "description", "tags",
        })
        if obj.raw_extra or obj.network_type != "layer3" or any(extra.values()):
            blockers.append("SOURCE_ZONE_BEHAVIOR_UNPROVEN")
        path = f"/api/fmc_config/v1/domain/{domain_id}/object/securityzones"
        body = {"name": row.target_name, "interfaceMode": "ROUTED", "type": "SecurityZone"}
        settings = (operation(row.key, path, body, "SecurityZone"), ("fmc_type", "SecurityZone"))
        result.append(item(obj, "zone", blockers=blockers, settings=settings))
    return result
