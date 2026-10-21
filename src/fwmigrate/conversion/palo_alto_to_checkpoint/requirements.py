"""Native source scope and explicit Check Point placement choices."""

from .models import CPMigrationDecision
from .planning.source_scope import source_scopes


def build_mapping_requirements(source, options):
    fields = [
        ("source_scope", "PAN-OS device / VSYS", options.source_scope, source_scopes(source)),
        ("management_api_version", "Management API version", options.management_api_version, ("1.8.1",)),
    ]
    if options.target_mode == "new":
        fields.append(("policy_package", "New policy package", options.policy_package, ()))
    if options.target_mode == "existing":
        fields.extend((key, label, getattr(options, key), ()) for key, label in (
            ("management_target", "Management server"), ("management_domain", "Management Domain")))
    return tuple(CPMigrationDecision(f"checkpoint:{key}", options.source_scope, "target", "Check Point",
                                    key, label, value, choices) for key, label, value, choices in fields if not value)


__all__ = ["source_scopes", "build_mapping_requirements"]
