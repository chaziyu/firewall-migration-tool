"""Bind an operator-declared complete ASA snapshot to its sanitized bytes."""


_REQUIRED = {"interfaces", "objects", "schedules", "routes", "access_rules", "acl_bindings", "nat"}


def build_target_evidence(target, target_digest, metadata):
    if not isinstance(metadata, dict):
        raise ValueError("ASA target comparison requires target metadata")
    if (metadata.get("context") != "single" or metadata.get("version") != "9.20"
            or metadata.get("mode") != "routed"):
        raise ValueError("ASA target metadata must select single-context routed ASA 9.20")
    families = metadata.get("complete_families")
    if not isinstance(families, list) or any(not isinstance(value, str) for value in families):
        raise ValueError("ASA complete_families must be a list of family names")
    config = getattr(getattr(target, "extracted", target), "config", target)
    if getattr(config, "multi_context_system", None) is not None or getattr(config, "contexts", ()):
        raise ValueError("Multi-context ASA target evidence is not supported")
    if getattr(config, "parse_errors", ()) or getattr(config, "unsupported_commands", ()):
        raise ValueError("ASA target configuration contains unparsed or unsupported commands")
    validation = getattr(target, "validation", None)
    if any(str(getattr(issue, "severity", "")).casefold() == "error" for issue in getattr(validation, "issues", ())):
        raise ValueError("ASA target validation errors prevent snapshot comparison")
    bindings = {}
    for binding in config.acl_bindings:
        if binding.interface and (binding.direction or "").casefold() == "in" and not binding.control_plane:
            bindings.setdefault(binding.interface, []).append(binding.acl_name)
    return {"digest": target_digest, "context": "single", "version": "9.20", "mode": "routed",
            "complete_families": sorted(set(families) & _REQUIRED), "existing_bindings": bindings,
            "config": config}
