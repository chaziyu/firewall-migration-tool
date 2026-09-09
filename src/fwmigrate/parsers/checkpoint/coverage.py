"""Authoritative Check Point extraction coverage accounting."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Hashable, Iterable, List, Mapping, Optional, Set, Tuple

from fwmigrate.extraction.models import (
    CoverageSummary,
    ExtractionStatus,
    SourceSectionResult,
)
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import (
    CheckPointExportBundle,
    CollectionStatus,
    CheckPointResponse,
    collection_status_is_success,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase


CHECKPOINT_COVERAGE_SECTIONS = (
    "Network Interfaces", "IPv4 Static Routes", "IPv6 Static Routes", "PBR",
    "DNS", "DHCP", "NTP", "SNMP", "Management Access", "Objects",
    "Services", "Schedules", "Access Control", "NAT", "VPN", "Authentication",
    "Identity Awareness", "Threat Prevention", "Application Control",
    "HTTPS Inspection", "ClusterXL", "SecureXL", "CoreXL", "Certificates",
    "SIC", "Policy Packages", "Access Layers", "Multi-Domain",
    "Global Assignments", "Other Check Point",
)

_COMMAND_SECTION = {
    "show-access-rulebase": "Access Control",
    "show-nat-rulebase": "NAT",
    "show-times": "Schedules",
    "show-time-groups": "Schedules",
    "show-server-certificates": "Certificates",
    "show-radius-servers": "Authentication",
    "show-packages": "Policy Packages",
    "show-access-layers": "Access Layers",
    "show-global-assignments": "Global Assignments",
    "show-domains": "Multi-Domain",
    "show-mdss": "Multi-Domain",
    "show-simple-clusters": "ClusterXL",
    "show-simple-gateways": "ClusterXL",
    "show-gateways-and-servers": "ClusterXL",
}
_SERVICE_COMMANDS = {
    "show-services-tcp", "show-services-udp", "show-services-sctp",
    "show-services-icmp", "show-services-icmp6", "show-services-other",
    "show-services-citrix-tcp", "show-services-dce-rpc", "show-services-rpc",
    "show-services-gtp", "show-services-compound-tcp", "show-service-groups",
}
_OBJECT_COMMANDS = {
    "show-hosts", "show-networks", "show-address-ranges", "show-groups",
    "show-groups-with-exclusion", "show-security-zones", "show-objects",
}
# Collection capability is section-scoped.  Optional families retain their
# unsupported evidence without making an absent family look like a failed
# configured object set.
SECTION_REQUIREMENTS = {
    "Objects": {
        "required_any": {"show-hosts", "show-networks", "show-address-ranges"},
        "optional": {"show-groups", "show-groups-with-exclusion", "show-security-zones"},
    },
    "Services": {"required_any": set(_SERVICE_COMMANDS), "optional": set()},
    "Access Control": {"required_any": {"show-access-rulebase"}, "optional": set()},
    "NAT": {"required_any": {"show-nat-rulebase"}, "optional": set()},
    "Certificates": {"required_any": {"show-server-certificates"}, "optional": set()},
}
_OPERATIONAL_TYPES = {
    "checkpoint-cluster-operational-state", "checkpoint-securexl-operational",
    "checkpoint-corexl-operational", "checkpoint-performance-operational",
}
_CRITICAL_REASONS = (
    "unresolved", "cross-domain", "blocked", "missing-access-layer",
    "missing-policy-package", "missing-inline", "placeholder", "failed-source-command",
)
_STATUS_RANK = {
    ExtractionStatus.NORMALIZED: 0,
    ExtractionStatus.EXTRACT_ONLY: 1,
    ExtractionStatus.PARTIALLY_NORMALIZED: 2,
    ExtractionStatus.UNSUPPORTED: 3,
    ExtractionStatus.PARSE_ERROR: 4,
}


def authoritative_object_identity(
    obj: Any,
    domain: str,
    source_scope: str,
) -> Tuple[Hashable, ...]:
    """Build a stable per-domain object key with conservative UID-less fallback."""
    if isinstance(obj, dict):
        uid = obj.get("uid")
        if uid:
            return (domain, "uid", str(uid))
        return (
            domain,
            "fallback",
            str(obj.get("type") or "<missing-type>"),
            str(obj.get("name") or "<missing-name>"),
            source_scope,
        )
    return (domain, "malformed", source_scope, repr(obj))


def _dictionary_entries(raw: Any) -> List[Any]:
    if isinstance(raw, dict):
        entries: List[Any] = []
        for key, value in raw.items():
            if isinstance(value, dict) and not value.get("uid") and key:
                value = {**value, "uid": str(key)}
            entries.append(value)
        return entries
    return list(raw) if isinstance(raw, list) else []


def count_authoritative_source_leaves(bundle: CheckPointExportBundle) -> int:
    """Count source constructs that require exactly one authoritative inventory record."""
    count = 0
    authoritative_object_keys: Set[Tuple[Hashable, ...]] = set()
    dictionary_occurrences: List[Tuple[Tuple[Hashable, ...], Any]] = []
    for response in bundle.responses:
        command = canonicalize_command(response.command)
        data = response.data
        domain = response.domain or bundle.domain or "global"
        if not collection_status_is_success(response.collection_status):
            count += 1
            continue
        if command == "gaia/show-configuration":
            text = str(data.get("cli_text", ""))
            count += sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))
            continue
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        if isinstance(objects, list):
            for obj in objects:
                identity = authoritative_object_identity(obj, domain, command)
                if identity not in authoritative_object_keys:
                    authoritative_object_keys.add(identity)
                    count += 1
        dictionary = data.get("objects-dictionary")
        for index, obj in enumerate(_dictionary_entries(dictionary)):
            dictionary_scope = f"{command}/objects-dictionary"
            if not isinstance(obj, dict):
                dictionary_scope = f"{dictionary_scope}:{index}"
            identity = authoritative_object_identity(obj, domain, dictionary_scope)
            dictionary_occurrences.append((identity, obj))
        rulebase = data.get("rulebase", [])
        if isinstance(rulebase, list):
            count += len(flatten_rulebase(rulebase))
    for identity, _ in dictionary_occurrences:
        if identity not in authoritative_object_keys:
            authoritative_object_keys.add(identity)
            count += 1
    return count


def _command_section(command: str) -> str:
    cmd = canonicalize_command(command)
    if cmd in _COMMAND_SECTION:
        return _COMMAND_SECTION[cmd]
    if cmd in _SERVICE_COMMANDS:
        return "Services"
    if cmd in _OBJECT_COMMANDS:
        return "Objects"
    if cmd == "gaia/show-configuration":
        return "Other Check Point"
    return "Other Check Point"


def checkpoint_source_category(command: str) -> str:
    """Return the stable coverage section for a Check Point command."""
    return _command_section(command)


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _item_command(item: Any) -> str:
    path = str(_value(item, "source_path", ""))
    path = path.removeprefix("checkpoint/")
    if path.startswith("gaia/show-configuration"):
        return "gaia/show-configuration"
    return path.split("/") [0] if path else ""


def _item_section(item: Any) -> str:
    source_type = str(_value(item, "source_type", "") or "").lower().replace("_", "-")
    path = str(_value(item, "source_path", "") or "").lower()
    attrs = _value(item, "source_attributes", {}) or {}
    if source_type in _OPERATIONAL_TYPES or "runtime-operational-evidence" in (_value(item, "notes", []) or []):
        if "securexl" in source_type:
            return "SecureXL"
        if "corexl" in source_type:
            return "CoreXL"
        return "ClusterXL" if "cluster" in source_type else "Other Check Point"
    if source_type.startswith("gaia-interface") or source_type.startswith(("gaia-vlan", "gaia-loopback", "gaia-bridge")):
        return "Network Interfaces"
    if source_type == "gaia-static-route":
        return "IPv6 Static Routes" if ":" in str(attrs.get("destination") or attrs.get("network") or "") else "IPv4 Static Routes"
    if source_type.startswith("gaia-pbr"):
        return "PBR"
    if source_type.startswith("gaia-dns") or source_type == "gaia-domain-name":
        return "DNS"
    if source_type.startswith("gaia-dhcp"):
        return "DHCP"
    if source_type.startswith("gaia-ntp"):
        return "NTP"
    if source_type.startswith("gaia-snmp"):
        return "SNMP"
    if source_type.startswith(("gaia-management", "gaia-web", "gaia-ssh", "gaia-rbac", "gaia-hostname-selection")):
        return "Management Access"
    if source_type.startswith("gaia-local-user") or source_type.startswith("gaia-user-group"):
        return "Authentication"
    if source_type.startswith("checkpoint-cluster") or source_type in {"simple-cluster", "cluster"}:
        return "ClusterXL"
    if source_type.startswith(("checkpoint-securexl", "securexl")):
        return "SecureXL"
    if source_type.startswith(("checkpoint-corexl", "corexl")):
        return "CoreXL"
    if source_type.startswith("checkpoint-certificate"):
        return "Certificates"
    if source_type == "checkpoint-sic-metadata":
        return "SIC"
    if source_type == "checkpoint-policy-package":
        return "Policy Packages"
    if source_type == "checkpoint-access-layer":
        return "Access Layers"
    if source_type == "checkpoint-global-assignment":
        return "Global Assignments"
    if source_type.startswith("checkpoint-domain"):
        return "Multi-Domain"
    if source_type == "access-rule":
        return "Access Control"
    if source_type == "nat-rule":
        return "NAT"
    if source_type.startswith("checkpoint-vpn"):
        return "VPN"
    if source_type.startswith(("checkpoint-auth", "checkpoint-ldap", "checkpoint-radius", "checkpoint-tacacs", "checkpoint-saml")):
        return "Authentication"
    if source_type == "access-role" or "identity" in source_type:
        return "Identity Awareness"
    if source_type.startswith(("threat-prevention", "checkpoint-threat")):
        return "Threat Prevention"
    if "https-inspection" in source_type or "https-inspection" in path:
        return "HTTPS Inspection"
    if "application" in source_type:
        return "Application Control"
    if source_type.startswith(("service", "checkpoint-service")):
        return "Services"
    if source_type.startswith(("time", "schedule", "checkpoint-time")):
        return "Schedules"
    command = _item_command(item)
    if "show-access-rulebase" in path:
        return "Access Control"
    if "show-nat-rulebase" in path:
        return "NAT"
    return _command_section(command)


def _evidence_class(item: Any) -> str:
    explicit = str(_value(item, "evidence_class", "") or "").lower()
    source_type = str(_value(item, "source_type", "") or "").lower()
    notes = {str(note).lower() for note in (_value(item, "notes", []) or [])}
    if explicit:
        return explicit
    if source_type in _OPERATIONAL_TYPES or any("runtime" in note or "operational" in note for note in notes):
        return "operational"
    if source_type == "collection-error":
        return "diagnostic"
    return "configuration"


def inventory_identity(item: Any) -> Tuple[Hashable, ...]:
    """Return a conservative identity that never merges objects across domains."""
    domain = _value(item, "domain_uid") or _value(item, "domain_name") or _value(item, "domain") or "global"
    source_id = _value(item, "source_id") or _value(item, "source_record_id")
    source_type = _value(item, "source_type") or ""
    if source_id:
        return (str(domain), "id", str(source_type), str(source_id))
    return (
        str(domain), "fallback", str(_value(item, "source_path", "")),
        str(source_type), str(_value(item, "name", "<unnamed>")),
    )


def _effective_status(item: Any) -> ExtractionStatus:
    raw = _value(item, "status", ExtractionStatus.EXTRACT_ONLY)
    try:
        status = ExtractionStatus(raw)
    except ValueError:
        status = ExtractionStatus.PARSE_ERROR
    notes = [str(note).lower() for note in (_value(item, "notes", []) or [])]
    name = str(_value(item, "name", "") or "").lower()
    if status == ExtractionStatus.NORMALIZED and (
        "placeholder" in name or any(any(reason in note for reason in _CRITICAL_REASONS) for note in notes)
    ):
        return ExtractionStatus.PARTIALLY_NORMALIZED
    if status == ExtractionStatus.VENDOR_EXTENSION:
        return ExtractionStatus.EXTRACT_ONLY
    return status


def _status_for_counts(statuses: Iterable[ExtractionStatus]) -> ExtractionStatus:
    values = list(statuses)
    if not values:
        return ExtractionStatus.NORMALIZED
    if ExtractionStatus.PARSE_ERROR in values:
        return ExtractionStatus.PARSE_ERROR
    if ExtractionStatus.UNSUPPORTED in values:
        return ExtractionStatus.UNSUPPORTED
    if ExtractionStatus.PARTIALLY_NORMALIZED in values:
        return ExtractionStatus.PARTIALLY_NORMALIZED
    if ExtractionStatus.NORMALIZED in values and ExtractionStatus.EXTRACT_ONLY in values:
        return ExtractionStatus.PARTIALLY_NORMALIZED
    if ExtractionStatus.EXTRACT_ONLY in values:
        return ExtractionStatus.EXTRACT_ONLY
    return ExtractionStatus.NORMALIZED


def _required_collection_failure(section: str, unsupported_commands: Set[str]) -> bool:
    requirements = SECTION_REQUIREMENTS.get(section)
    if requirements is None:
        return bool(unsupported_commands)
    optional = requirements.get("optional", set())
    required_any = requirements.get("required_any", set())
    if any(command not in optional for command in unsupported_commands if command not in required_any):
        return True
    # Once the section has source objects, an unavailable required family is
    # incomplete even when another family was collected successfully.
    return bool(required_any & unsupported_commands)


def _add_reason(target: Set[str], values: Iterable[Any]) -> None:
    target.update(str(value) for value in values if value)


def aggregate_checkpoint_coverage(
    items: Iterable[Any],
    responses: Iterable[CheckPointResponse] = (),
    collection_completeness: Optional[Mapping[str, Any]] = None,
) -> List[CoverageSummary]:
    """Aggregate final inventory and collection evidence by domain and stable section."""
    groups: Dict[Tuple[Optional[str], Optional[str], str, bool], Dict[str, Any]] = {}
    seen: Dict[Tuple[Optional[str], Optional[str], str, bool], Dict[Tuple[Hashable, ...], Any]] = defaultdict(dict)

    def group(domain: Optional[str], domain_name: Optional[str], section: str, operational: bool) -> Dict[str, Any]:
        key = (domain, domain_name, section, operational)
        return groups.setdefault(key, {
            "statuses": [], "items": [], "commands": set(), "reasons": set(),
            "errors": set(), "supported_empty": False, "unsupported_commands": set(),
            "collection_statuses": [],
        })

    for item in items:
        operational = _evidence_class(item) in {"operational", "diagnostic"} and _evidence_class(item) != "diagnostic"
        domain_uid = _value(item, "domain_uid")
        domain_name = _value(item, "domain_name") or _value(item, "domain") or "global"
        section = _item_section(item)
        state = group(domain_uid, domain_name, section, operational)
        identity = inventory_identity(item)
        current = seen[(domain_uid, domain_name, section, operational)].get(identity)
        if current is not None and _STATUS_RANK.get(_effective_status(item), 4) <= _STATUS_RANK.get(_effective_status(current), 4):
            continue
        seen[(domain_uid, domain_name, section, operational)][identity] = item

    for key, identities in seen.items():
        state = groups[key]
        for item in identities.values():
            status = _effective_status(item)
            state["statuses"].append(status)
            state["items"].append(item)
            command = _item_command(item)
            if command:
                state["commands"].add(command)
            _add_reason(state["reasons"], _value(item, "notes", []))

    for response in responses:
        command = canonicalize_command(response.command)
        section = _command_section(command)
        domain_uid = response.domain_uid
        domain_name = response.domain_name or response.domain or "global"
        state = group(domain_uid, domain_name, section, False)
        state["commands"].add(command)
        status = response.collection_status
        state["collection_statuses"].append(status)
        if status == CollectionStatus.SUCCESS_EMPTY:
            state["supported_empty"] = True
        elif status == CollectionStatus.UNSUPPORTED_COMMAND:
            state["unsupported_commands"].add(command)
            state["errors"].add(f"{command}:UNSUPPORTED_COMMAND")
        elif not collection_status_is_success(status):
            state["errors"].add(f"{command}:{getattr(status, 'value', status)}")
            if response.error:
                state["reasons"].add(str(response.error))

    for record in (collection_completeness or {}).values():
        command = canonicalize_command(_value(record, "command", ""))
        if not command:
            continue
        state = group(_value(record, "domain_uid"), _value(record, "domain_name") or _value(record, "domain") or "global", _command_section(command), False)
        state["commands"].add(command)
        status = _value(record, "status")
        state["collection_statuses"].append(status)
        if status == CollectionStatus.SUCCESS_EMPTY or status == CollectionStatus.SUCCESS_EMPTY.value:
            state["supported_empty"] = True
        elif status in {CollectionStatus.UNSUPPORTED_COMMAND, CollectionStatus.UNSUPPORTED_COMMAND.value}:
            state["unsupported_commands"].add(command)
            state["errors"].add(f"{command}:UNSUPPORTED_COMMAND")
        elif status and not collection_status_is_success(status):
            state["errors"].add(f"{command}:{getattr(status, 'value', status)}")

    summaries: List[CoverageSummary] = []
    for (domain_uid, domain_name, section, operational), state in groups.items():
        statuses = list(state["statuses"])
        commands = set(state["commands"])
        collection_errors = set(state["errors"])
        reasons = set(state["reasons"])
        if state["supported_empty"] and not statuses:
            reasons.add("supported-empty")
        required_failure = _required_collection_failure(section, state["unsupported_commands"])
        collection_failure = any(
            not error.endswith(":UNSUPPORTED_COMMAND") for error in collection_errors
        )
        if state["unsupported_commands"]:
            reasons.add("unsupported-source-command")
        if collection_failure:
            reasons.add("collection-requires-review")
        if state["supported_empty"] and not statuses:
            reasons.add("supported-empty")
        if not statuses:
            if not state["supported_empty"] and not state["unsupported_commands"] and not collection_failure:
                reasons.add("not-assessed")
        counts = {status: statuses.count(status) for status in _STATUS_RANK}
        effective = _status_for_counts(statuses)
        if collection_failure:
            effective = ExtractionStatus.PARSE_ERROR
        elif required_failure:
            effective = ExtractionStatus.UNSUPPORTED
        elif not statuses:
            effective = ExtractionStatus.PARTIALLY_NORMALIZED
        summaries.append(CoverageSummary(
            section=section, domain=domain_name, domain_uid=domain_uid,
            domain_name=domain_name, scope="domain", operational=operational,
            status=effective, total=sum(counts.values()),
            normalized=counts[ExtractionStatus.NORMALIZED],
            partial=counts[ExtractionStatus.PARTIALLY_NORMALIZED],
            extract_only=counts[ExtractionStatus.EXTRACT_ONLY],
            unsupported=counts[ExtractionStatus.UNSUPPORTED],
            parse_errors=counts[ExtractionStatus.PARSE_ERROR],
            supported_empty=state["supported_empty"],
            collection_errors=sorted(collection_errors),
            review_reasons=sorted(reasons), source_commands=sorted(commands),
        ))

    # Overall summaries are derived from the domain summaries, never by taking
    # the first or largest domain.
    by_overall: Dict[Tuple[str, bool], List[CoverageSummary]] = defaultdict(list)
    for summary in summaries:
        by_overall[(summary.section, summary.operational)].append(summary)
    for (section, operational), entries in by_overall.items():
        statuses = [entry.status for entry in entries]
        summaries.append(CoverageSummary(
            section=section, domain=None, domain_name="overall", scope="overall",
            operational=operational, status=_status_for_counts(statuses),
            total=sum(entry.total for entry in entries),
            normalized=sum(entry.normalized for entry in entries),
            partial=sum(entry.partial for entry in entries),
            extract_only=sum(entry.extract_only for entry in entries),
            unsupported=sum(entry.unsupported for entry in entries),
            parse_errors=sum(entry.parse_errors for entry in entries),
            supported_empty=any(entry.supported_empty for entry in entries),
            collection_errors=sorted({error for entry in entries for error in entry.collection_errors}),
            review_reasons=sorted({reason for entry in entries for reason in entry.review_reasons}),
            source_commands=sorted({command for entry in entries for command in entry.source_commands}),
        ))
    return sorted(summaries, key=lambda item: (item.scope, item.domain_name or "", item.section, item.operational))


def apply_checkpoint_coverage(
    sections: List[SourceSectionResult], summaries: List[CoverageSummary],
) -> None:
    """Project authoritative summaries onto legacy per-command section records."""
    lookup = {
        (item.domain_uid, item.domain_name, item.section, item.operational): item
        for item in summaries if item.scope == "domain"
    }
    for section in sections:
        command = _item_command({"source_path": section.path})
        category = _command_section(command)
        domain_name = section.domain_name or section.source_context or "global"
        summary = next((item for (uid, domain, name, operational), item in lookup.items()
                        if domain == domain_name and name == category and not operational), None)
        if summary is None:
            continue
        section.coverage_section = summary.section
        section.domain_uid = summary.domain_uid
        section.domain_name = summary.domain_name
        section.object_count_total = summary.total
        section.object_count_normalized = summary.normalized
        section.object_count_partial = summary.partial
        section.object_count_extract_only = summary.extract_only
        section.object_count_unsupported = summary.unsupported
        section.object_count_parse_error = summary.parse_errors
        section.supported_empty = summary.supported_empty
        section.collection_errors = summary.collection_errors
        section.review_reasons = summary.review_reasons
        section.source_commands = summary.source_commands
        section.status = summary.status


def create_section_result(
    command: str,
    domain: Optional[str] = None,
    package: Optional[str] = None,
    layer: Optional[str] = None,
    gateway: Optional[str] = None,
    source_count: int = 0,
    parsed_count: int = 0,
    normalized_count: int = 0,
    status: ExtractionStatus = ExtractionStatus.NORMALIZED,
    parser_handler: Optional[str] = None,
    notes: Optional[List[str]] = None,
) -> SourceSectionResult:
    """Construct a backward-compatible section record with stable identity."""
    cmd = canonicalize_command(command)
    parts = ["checkpoint", cmd]
    if domain:
        parts.append(domain)
    if cmd == "show-access-rulebase":
        parts.extend([package or "<missing-package>", layer or "<missing-layer>"])
    elif cmd == "show-nat-rulebase":
        parts.append(package or "<missing-package>")
    else:
        if package:
            parts.append(package)
        if layer:
            parts.append(layer)
    if gateway:
        parts.append(gateway)
    return SourceSectionResult(
        path="/".join(parts), source_context=domain, domain_name=domain,
        present=True, object_count_source=source_count,
        object_count_parsed=parsed_count, object_count_normalized=normalized_count,
        object_count_total=source_count, coverage_section=_command_section(cmd),
        status=status, parser_handler=parser_handler or f"checkpoint.{cmd}",
        notes=notes or [], source_commands=[cmd],
    )


def account_inventory_items(items: List[Any]) -> Tuple[int, int, int, ExtractionStatus]:
    """Compatibility helper derived from final inventory statuses."""
    statuses = [_effective_status(item) for item in items if _evidence_class(item) == "configuration"]
    if not statuses:
        return 0, 0, 0, ExtractionStatus.PARTIALLY_NORMALIZED if items else ExtractionStatus.NORMALIZED
    status = _status_for_counts(statuses)
    return (
        len(statuses),
        sum(value != ExtractionStatus.PARSE_ERROR for value in statuses),
        statuses.count(ExtractionStatus.NORMALIZED),
        status,
    )
