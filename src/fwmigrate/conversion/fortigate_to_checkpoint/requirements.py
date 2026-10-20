"""Explicit source-scope and Check Point target choices."""

from .models import CPMigrationDecision


def source_vdoms(source):
    values = set()
    for family in ("addresses", "address_groups", "services", "service_groups", "policies", "static_routes", "interfaces", "zones"):
        for row in getattr(source, family, ()):
            values.add(row.vdom or "root")
    return tuple(sorted(values))


def build_mapping_requirements(source, options):
    requirements = (
        ("source_vdom", "Source FortiGate VDOM", options.source_vdom, source_vdoms(source)),
        ("management_target", "Check Point Management target label", options.management_target, ()),
        ("management_domain", "Management Domain", options.management_domain, ()),
        ("management_api_version", "Management API version", options.management_api_version, ("1.8.1",)),
        ("policy_package", "Policy package", options.policy_package, ()),
        ("access_layer", "Access layer", options.access_layer, ()),
        ("install_on", "Install-on gateway or cluster", ", ".join(options.install_on), ()),
        ("insertion_relation", "Insert rules relative to cleanup rule", options.insertion_relation, ("above",)),
        ("insertion_anchor", "Existing Drop cleanup rule anchor", options.insertion_anchor, ()),
        ("target_cleanup_action", "Confirmed target cleanup action", options.target_cleanup_action, ("Drop",)),
        ("gaia_target", "Gaia gateway or cluster", options.gaia_target, ()),
    )
    return tuple(CPMigrationDecision(f"checkpoint:{key}", options.source_vdom, "target", "Check Point",
                                     key, label, value, tuple(choices))
                 for key, label, value, choices in requirements if not value
                 and (options.target_mode == "existing" or key in {"source_vdom", "management_api_version", "policy_package"}))

