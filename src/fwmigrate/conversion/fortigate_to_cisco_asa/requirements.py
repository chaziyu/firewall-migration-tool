"""Pair-specific review requirements for ASA target placement."""

from .models import ASAMigrationDecision
from .planning.naming import decision_key


def source_vdoms(source):
    values = set()
    for field in type(source).model_fields:
        rows = getattr(source, field, None)
        if isinstance(rows, (list, tuple)):
            values.update((item.vdom or "root") for item in rows if hasattr(item, "vdom"))
    return tuple(sorted(values))


def build_mapping_requirements(source, options):
    vdoms = source_vdoms(source)
    result = [ASAMigrationDecision(decision_key(None, "source", "FortiGate", "source_vdom"), None,
                                   "source", "FortiGate", "source_vdom", "FortiGate VDOM",
                                   options.source_vdom, vdoms)]
    for field, label, values in (("target_context", "ASA context", ("single",)),
                                 ("target_version", "Cisco ASA syntax baseline", ("9.20",)),
                                 ("target_mode", "ASA firewall mode", ("routed",))):
        result.append(ASAMigrationDecision(decision_key(None, "target", "Cisco ASA", field), None,
                                           "target", "Cisco ASA", field, label, getattr(options, field), values))
    if options.source_vdom in vdoms:
        for item in source.interfaces:
            vdom = item.vdom or "root"
            if vdom != options.source_vdom:
                continue
            mapping = options.interfaces.get(vdom, {}).get(item.name)
            value = None if mapping is None else {"interface": mapping.interface, "nameif": mapping.nameif,
                                                   "security_level": mapping.security_level}
            result.append(ASAMigrationDecision(decision_key(vdom, "interface", item.name, "asa_interface"), vdom,
                                               "interface", item.name, "asa_interface", "ASA interface, nameif, and security level", value))
    if options.source_timezone or options.target_timezone:
        result.append(ASAMigrationDecision(decision_key(None, "schedule", "time-zone", "equivalence"), None,
                                           "schedule", "Time zone", "equivalence", "Source and ASA local time zone",
                                           {"source": options.source_timezone, "target": options.target_timezone}))
    for name, evidence in sorted(options.nat_evidence.items()):
        result.append(ASAMigrationDecision(decision_key(options.source_vdom, "nat", name, "translation_evidence"),
                                           options.source_vdom, "nat", name, "translation_evidence",
                                           "NAT placement, return route, and proxy ARP evidence", evidence))
    return tuple(result)
