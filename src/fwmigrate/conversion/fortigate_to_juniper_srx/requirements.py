"""Required engineer choices for the FortiGate to Juniper SRX pair."""

from dataclasses import asdict

from .models import SRXMigrationDecision
from .options import SRXMigrationOptions
from .planning.naming import decision_key


_TARGET_CHOICES = (
    ("target_context", "root", ("root",)),
    ("target_version", "25.2R1", ("25.2R1",)),
    ("target_mode", "standalone", ("standalone",)),
    ("routing_table", "inet.0", ("inet.0",)),
)


def source_vdoms(source) -> tuple[str, ...]:
    values = set()
    for field_name in type(source).model_fields:
        collection = getattr(source, field_name, None)
        if not isinstance(collection, (list, tuple)):
            continue
        values.update(item.vdom for item in collection if getattr(item, "vdom", None))
    return tuple(sorted(values))


def _decision(source_vdom, source_kind, source_name, target_field, label, value, choices=()):
    return SRXMigrationDecision(
        key=decision_key(source_vdom, source_kind, source_name, target_field),
        source_vdom=source_vdom,
        source_kind=source_kind,
        source_name=source_name,
        target_field=target_field,
        label=label,
        value=value,
        review_state="CONFIRMED" if value is not None else "PENDING",
        choices=tuple(choices),
    )


def build_mapping_requirements(source, derived, options: SRXMigrationOptions | None = None) -> tuple[SRXMigrationDecision, ...]:
    options = options or SRXMigrationOptions()
    vdoms = source_vdoms(source)
    decisions = [
        _decision(None, "source", "FortiGate", "source_vdom", "FortiGate VDOM", options.source_vdom, vdoms),
    ]
    decisions.extend(
        _decision(None, "target", "Juniper SRX", field, label, getattr(options, field), choices)
        for field, label, choices in (
            ("target_context", "Target context", ("root",)),
            ("target_version", "Junos version", ("25.2R1",)),
            ("target_mode", "Target operating mode", ("standalone",)),
            ("routing_table", "Routing table", ("inet.0",)),
        )
    )
    decisions.append(_decision(
        None, "target", "Juniper SRX", "timezone",
        "Confirmed FortiGate and SRX system timezone", options.timezone,
    ))
    for vdom in vdoms:
        for interface in source.interfaces:
            if interface.vdom != vdom:
                continue
            mapping = options.interfaces.get(vdom, {}).get(interface.name)
            decisions.append(_decision(
                vdom, "interface", interface.name, "target_interface",
                f"Target interface for {vdom}/{interface.name}",
                asdict(mapping) if mapping else None,
            ))
        for zone in source.zones:
            if zone.vdom != vdom:
                continue
            value = options.zones.get(vdom, {}).get(zone.name)
            decisions.append(_decision(
                vdom, "zone", zone.name, "target_zone",
                f"Target security zone for {vdom}/{zone.name}", value,
            ))
    return tuple(decisions)
