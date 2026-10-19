"""Conservative exact object reuse and an explicitly empty access-rule slice."""

from collections import defaultdict
from dataclasses import replace

from ..models import CPFinding


def _reference_name(value):
    return value if isinstance(value, str) else getattr(value, "name", None)


def _matches(obj, operation):
    body = operation["request_body_template"]
    if obj.raw_extra:
        return False
    path = operation["path"]
    if path == "/web_api/add-host" and "ipv6-address" in body:
        return (obj.object_type == "host" and obj.ipv6_address == body["ipv6-address"]
                and not obj.ipv4_address and obj.nat_settings == {"auto-rule": False})
    if path == "/web_api/add-network" and "subnet6" in body:
        return (obj.object_type == "network" and obj.subnet6 == body["subnet6"]
                and obj.mask_length6 == body["mask-length6"] and not obj.subnet4
                and obj.nat_settings == {"auto-rule": False})
    if path == "/web_api/add-host":
        return (
            obj.object_type == "host"
            and obj.ipv4_address == body.get("ipv4-address")
            and not obj.ipv6_address
            and obj.nat_settings == {"auto-rule": False}
        )
    if path == "/web_api/add-network":
        return (
            obj.object_type == "network"
            and obj.subnet4 == body.get("subnet4")
            and obj.mask_length4 == body.get("mask-length4")
            and not obj.subnet6
            and obj.nat_settings == {"auto-rule": False}
        )
    if path == "/web_api/add-address-range":
        return (
            obj.object_type == "address-range"
            and obj.ipv4_address_first == body.get("ipv4-address-first")
            and obj.ipv4_address_last == body.get("ipv4-address-last")
            and obj.nat_settings == {"auto-rule": False}
        )
    if path in {"/web_api/add-service-tcp", "/web_api/add-service-udp"}:
        return (
            obj.object_type == path.removeprefix("/web_api/add-")
            and str(obj.port) == body.get("port")
            and str(obj.source_port) == body.get("source-port", "1-65535")
            and obj.match is None
            and obj.session_timeout is None
        )
    return False


def _policy_context(config, options):
    if config.nat_rules or any(
        obj.nat_settings != {"auto-rule": False}
        for obj in (*config.hosts, *config.networks, *config.address_ranges)
    ):
        return None
    packages = [
        obj for obj in config.policy_packages if obj.name == options["policy_package"]
    ]
    layers = [
        obj for obj in config.access_layers if obj.name == options["access_layer"]
    ]
    if (
        len(packages) != 1
        or len(layers) != 1
        or not packages[0].uid
        or not layers[0].uid
        or packages[0].raw_extra
        or layers[0].raw_extra
    ):
        return None
    layer = layers[0]
    layer_refs = packages[0].access_layers or ()
    if len(layer_refs) != 1 or not any(
        (ref if isinstance(ref, str) else ref.uid) == layer.uid for ref in layer_refs
    ):
        return None
    gateways = {
        obj.name: obj.uid for obj in (*config.gateways, *config.clusters) if obj.uid
    }
    if any(
        name not in gateways
        or sum(obj.name == name for obj in (*config.gateways, *config.clusters)) != 1
        for name in options["install_on"]
    ):
        return None
    rules = [obj for obj in config.access_rules if obj.layer_uid == layer.uid]
    # shortcut: only a cleanup-only layer proves the initial additive slice; extend with ordered packet-flow fixtures.
    if len(rules) != 1 or any(
        obj.layer_uid == layer.uid for obj in config.access_sections
    ):
        return None
    rule = rules[0]
    if (
        rule.uid is None
        or options["insertion_anchor"] not in {rule.uid, rule.name}
        or rule.enabled is not True
        or _reference_name(rule.action) != "Drop"
        or rule.inline_layer is not None
        or rule.raw_extra
        or rule.source_negate is not False
        or rule.destination_negate is not False
    ):
        return None
    if any(
        [_reference_name(ref) for ref in getattr(rule, field) or ()] != ["Any"]
        for field in ("source", "destination", "service", "time", "vpn", "content")
    ):
        return None
    install_on = {_reference_name(ref) for ref in rule.install_on or ()}
    if not set(options["install_on"]) <= install_on:
        return None
    return layer.uid, rule.uid, gateways


def classify_target_reuse(plan, evidence):
    names = defaultdict(list)
    for obj in evidence["objects"]:
        if obj.name:
            names[obj.name.casefold()].append(obj)
    context = _policy_context(evidence["config"], plan.options)
    families = evidence["complete_families"]
    items = []
    for item in plan.items:
        blockers = list(item.blockers)
        settings = dict(item.settings)
        disposition = None
        if item.family == "static_route":
            blockers.append("GAIA_DESTINATION_EVIDENCE_REQUIRED")
        elif item.family in {"address", "address6", "service"}:
            required = "services" if item.family == "service" else "objects"
            if required not in families or "nat" not in families:
                blockers.append("TARGET_OBJECT_FAMILY_INCOMPLETE")
            else:
                existing = names[item.target_name.casefold()]
                operation = settings.get("management_operation")
                if existing:
                    if (
                        len(existing) == 1
                        and existing[0].uid
                        and operation
                        and _matches(existing[0], operation)
                    ):
                        disposition = "REUSE"
                        settings["target_uid"] = existing[0].uid
                    else:
                        blockers.append(
                            "TARGET_OBJECT_COLLISION_OR_EQUIVALENCE_UNKNOWN"
                        )
        elif item.family == "policy":
            if (
                not {"packages", "layers", "gateways", "policies", "nat"} <= families
                or context is None
            ):
                blockers.append("TARGET_POLICY_CONTEXT_UNVERIFIED")
            elif names[item.target_name.casefold()]:
                blockers.append("TARGET_RULE_COLLISION")
            elif settings.get("management_operation"):
                operation = dict(settings["management_operation"])
                body = dict(operation["request_body_template"])
                layer_uid, cleanup_uid, gateways = context
                body["layer"] = layer_uid
                body["install-on"] = [
                    gateways[name] for name in plan.options["install_on"]
                ]
                if body["position"] == {"above": plan.options["insertion_anchor"]}:
                    body["position"] = {"above": cleanup_uid}
                settings["management_operation"] = {
                    **operation,
                    "request_body_template": body,
                }
        items.append(
            replace(
                item,
                settings=tuple(settings.items()),
                blockers=tuple(dict.fromkeys(blockers)),
                target_disposition=disposition,
            )
        )
    findings = tuple(
        row for row in plan.findings if row.code != "DESTINATION_NOT_COMPARED"
    )
    findings += (
        CPFinding(
            "DESTINATION_SNAPSHOT_COMPARED",
            "Management snapshot compared; Gaia and live device acceptance remain unverified.",
            blocking=False,
        ),
    )
    return replace(plan, items=tuple(items), findings=findings)
