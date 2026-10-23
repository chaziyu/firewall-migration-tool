"""Validated native FMC REST export evidence."""

from collections import Counter

from ..design.deterministic import digest


FAMILIES = {"objects", "services", "zones", "devices", "policies", "nat"}


def build_target_evidence(analysis, source_text, metadata, options):
    if not isinstance(source_text, str) or not isinstance(metadata, dict):
        raise ValueError("Cisco FTD comparison requires sanitized source and explicit metadata")

    if (
        (options.domain_name and metadata.get("context") != options.domain_name and metadata.get("context") != options.domain_id)
        or (options.fmc_api_version and metadata.get("version") != options.fmc_api_version)
        or metadata.get("mode") not in {"fmc", "management", "fmc-rest-bundle"}
    ):
        raise ValueError("Cisco FTD destination scope or version differs from the design")

    families = metadata.get("complete_families")
    if (
        not isinstance(families, list)
        or any(not isinstance(value, str) for value in families)
        or len(families) != len(set(families))
        or not set(families) <= FAMILIES
    ):
        raise ValueError("Declare valid complete Cisco FMC evidence families")

    config = analysis.config
    native_domain = (getattr(config, "source_metadata", {}) or {}).get("domain_id")
    if not options.domain_id or native_domain != options.domain_id:
        raise ValueError("Cisco FTD destination domain UUID differs from the design or is missing")
    if getattr(config, "source_plane", None) not in {"fmc", "fmc-rest-bundle"}:
        raise ValueError("Cisco FTD destination evidence must be an authoritative FMC REST bundle")

    if hasattr(config, "collection_metadata"):
        coll_meta = config.collection_metadata
        if coll_meta and getattr(coll_meta, "status", None) in {"FAILED", "UNKNOWN"}:
            raise ValueError("Incomplete FMC collection cannot prove target absence")

    # Check for duplicate IDs
    all_objects = [
        *getattr(config, "network_addresses", ()),
        *getattr(config, "protocol_port_objects", ()),
        *getattr(config, "security_zones", ()),
        *getattr(config, "network_groups", ()),
        *getattr(config, "port_object_groups", ()),
    ]
    ids = [
        getattr(obj, "source_id", None) or getattr(obj, "id", None) or (getattr(obj, "raw_extra", {}) or {}).get("id")
        for obj in all_objects
    ]
    valid_ids = [i for i in ids if i]
    if any(count > 1 for count in Counter(valid_ids).values()):
        raise ValueError("Duplicate destination object IDs are ambiguous")

    return {
        "config": config,
        "network_addresses": list(getattr(config, "network_addresses", ())),
        "protocol_port_objects": list(getattr(config, "protocol_port_objects", ())),
        "security_zones": list(getattr(config, "security_zones", ())),
        "network_groups": list(getattr(config, "network_groups", ())),
        "port_object_groups": list(getattr(config, "port_object_groups", ())),
        "devices": list(getattr(config, "devices", ())),
        "interfaces": list(getattr(config, "interfaces", ())),
        "complete_families": set(families),
        "digest": digest({"source": source_text, "metadata": metadata}),
    }
