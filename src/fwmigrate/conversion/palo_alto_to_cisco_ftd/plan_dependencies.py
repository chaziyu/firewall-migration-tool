"""Iterative dependency checks for Cisco FMC operation plans."""

from collections import defaultdict
import heapq
import re


_FMC_PATH_PATTERNS = {
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/hosts$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/networks$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/ranges$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/networkgroups$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/protocolportobjects$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/portobjectgroups$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/object/securityzones$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/policy/accesspolicies$"),
    re.compile(r"^/api/fmc_config/v1/domain/[^/]+/policy/accesspolicies/[^/]+/accessrules$"),
}


def ordered_items(plan):
    by_key = {item.key: item for item in plan.items}
    indegree = {key: 0 for key in by_key}
    dependents = defaultdict(list)
    for item in plan.items:
        for dependency in item.dependencies:
            if dependency not in by_key:
                raise ValueError("Cisco FTD plan contains an unresolved dependency")
            indegree[item.key] += 1
            dependents[dependency].append(item.key)
    order = {item.key: index for index, item in enumerate(plan.items)}
    ready = [(order[item.key], item.key) for item in plan.items if indegree[item.key] == 0]
    heapq.heapify(ready)
    result = []
    while ready:
        _, key = heapq.heappop(ready)
        result.append(by_key[key])
        for dependent in dependents[key]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, (order[dependent], dependent))
    if len(result) != len(plan.items):
        raise ValueError("Cisco FTD plan contains a dependency cycle")
    return tuple(result)


def validate_plan(plan):
    keys = [item.key for item in plan.items]
    if len(keys) != len(set(keys)):
        raise ValueError("Cisco FTD plan contains duplicate item keys")
    ordered = ordered_items(plan)
    bindings = {}
    blocked = set()
    for item in ordered:
        settings = dict(item.settings)
        if item.target_disposition not in {None, "CREATE", "REUSE", "BLOCK"}:
            raise ValueError("Invalid Cisco FTD target disposition")
        if item.target_disposition == "REUSE" and not isinstance(settings.get("target_id"), str):
            raise ValueError("Reused FMC objects require a verified ID")
        if item.blockers or item.target_disposition == "BLOCK" or any(key in blocked for key in item.dependencies):
            blocked.add(item.key)
        operation = settings.get("fmc_operation")
        if operation is not None:
            path = operation.get("path", "")
            # Normalized path for pattern matching
            norm_path = re.sub(r"\{\$response_binding:[^}]+\}", "placeholder_uuid", path)
            if not any(pattern.match(norm_path) for pattern in _FMC_PATH_PATTERNS):
                raise ValueError("Cisco FTD plan contains an unverified FMC API path")
            binding = operation.get("response_binding", {}).get("binding_id")
            if binding:
                if binding in bindings:
                    raise ValueError("Cisco FTD plan contains a duplicate response binding")
                bindings[binding] = item.key

    for item in ordered:
        operation = dict(item.settings).get("fmc_operation")
        if operation is None or item.key in blocked:
            continue
        allowed_dependencies = set(item.dependencies)
        for binding in _response_bindings(operation.get("request_body_template")):
            dependency = bindings.get(binding)
            if dependency is None or dependency not in allowed_dependencies:
                raise ValueError("FMC API request references an unbound or undeclared ID dependency")
        for binding in _response_bindings_in_path(operation.get("path", "")):
            dependency = bindings.get(binding)
            if dependency is None or dependency not in allowed_dependencies:
                raise ValueError("FMC API request path references an unbound or undeclared ID dependency")
    return plan


def _response_bindings(value):
    if isinstance(value, dict):
        if set(value) == {"$response_binding"}:
            yield value["$response_binding"]
        else:
            for child in value.values():
                yield from _response_bindings(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            yield from _response_bindings(child)


def _response_bindings_in_path(path):
    for match in re.finditer(r"\{\$response_binding:\s*([^}]+)\}", path):
        yield match.group(1).strip()


def dispositions(plan):
    validate_plan(plan)
    result = {}
    owners = defaultdict(list)
    for item in plan.items:
        if item.family in {"address", "address_group", "service", "service_group", "zone", "acp"}:
            owners[item.target_name.casefold()].append(item.key)
    ambiguous = {key for keys in owners.values() if len(keys) > 1 for key in keys}
    for item in ordered_items(plan):
        blocked_dependency = any(result[dependency] == "BLOCK" for dependency in item.dependencies)
        result[item.key] = "BLOCK" if item.blockers or blocked_dependency or item.key in ambiguous else item.target_disposition or "CREATE"
    return result
