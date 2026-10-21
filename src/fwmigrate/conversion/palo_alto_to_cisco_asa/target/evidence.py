"""Conservative native ASA object evidence. Existing traffic placement is unsupported."""

from dataclasses import dataclass
import hashlib
import json


FAMILIES = {"addresses", "services", "interfaces", "static_routes", "policies", "nat", "acl_bindings"}


@dataclass(frozen=True, slots=True)
class ASATargetEvidence:
    digest: str
    context: str
    version: str
    mode: str
    complete_families: frozenset[str]
    blocks: tuple[tuple[str, tuple[str, ...]], ...]
    global_blockers: tuple[str, ...]
    family_blockers: tuple[tuple[str, tuple[str, ...]], ...]

    def blockers_for(self, family):
        return dict(self.family_blockers).get(family, ())


def build_target_evidence(analysis, source_text, metadata, options):
    if not isinstance(source_text, str) or not source_text.strip():
        raise ValueError("Native ASA target configuration required")
    metadata = metadata if isinstance(metadata, dict) else {}
    declared = metadata.get("complete_families")
    complete = frozenset(row for row in declared if isinstance(row, str)) if isinstance(declared, list) else frozenset()
    blockers = []
    context, version, mode = (metadata.get(key, "") for key in ("context", "version", "mode"))
    if (context, version, mode) != (options.target_context, options.target_version, options.target_mode):
        blockers.append("TARGET_PROFILE_MISMATCH")
    if not isinstance(declared, list) or len(complete) != len(declared) or not complete <= FAMILIES:
        blockers.append("TARGET_COMPLETENESS_MANIFEST_INVALID")
    if any(str(getattr(issue, "severity", "")).lower() == "error" for issue in analysis.validation.issues):
        blockers.append("TARGET_VALIDATION_ERRORS")
    blocks, current = {}, None
    for line in source_text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line in {"exit", "end"}:
            current = None
            continue
        if line.startswith(("object network ", "object-group network ", "object-group service ")):
            if line in blocks:
                blockers.append("TARGET_DUPLICATE_OBJECT_HEADER")
            blocks[line] = []
            current = line
        elif current and line.startswith(("host ", "subnet ", "range ", "network-object ", "service-object ", "group-object ")):
            blocks[current].append(line)
        else:
            current = None
            # Target mode/ownership and all unknown target semantics remain fail closed.
            if not line.startswith(("hostname ", "ASA Version ", "interface ", "nameif ", "security-level ",
                                    "ip address ", "no shutdown", "route ", "access-list ", "access-group ",
                                    "nat ", "same-security-traffic ")):
                blockers.append("TARGET_UNMODELED_CONFIGURATION")
    identity = json.dumps({"source_sha256": hashlib.sha256(source_text.encode()).hexdigest(), "metadata": metadata}, sort_keys=True).encode()
    return ASATargetEvidence(hashlib.sha256(identity).hexdigest(), context, version, mode, complete,
                             tuple((header, tuple(lines)) for header, lines in blocks.items()),
                             tuple(dict.fromkeys(blockers)),
                             tuple((family, () if family in complete else ("TARGET_FAMILY_COMPLETENESS_UNCONFIRMED",)) for family in FAMILIES))
