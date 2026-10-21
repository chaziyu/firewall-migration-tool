"""Iterative dependency checks for Check Point operation plans."""

from collections import defaultdict
import heapq


_MANAGEMENT_PATHS = {
    "/web_api/add-package",
    "/web_api/add-host",
    "/web_api/add-network",
    "/web_api/add-address-range",
    "/web_api/add-group",
    "/web_api/add-service-group",
    "/web_api/set-access-layer",
    "/web_api/add-service-tcp",
    "/web_api/add-service-udp",
    "/web_api/add-access-rule",
}


def ordered_items(plan):
    by_key = {item.key: item for item in plan.items}
    indegree = {key: 0 for key in by_key}
    dependents = defaultdict(list)
    for item in plan.items:
        for dependency in item.dependencies:
            if dependency not in by_key:
                raise ValueError("Check Point plan contains an unresolved dependency")
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
        raise ValueError("Check Point plan contains a dependency cycle")
    return tuple(result)


def validate_plan(plan):
    keys = [item.key for item in plan.items]
    if len(keys) != len(set(keys)):
        raise ValueError("Check Point plan contains duplicate item keys")
    ordered = ordered_items(plan)
    bindings = {}
    blocked = set()
    for item in ordered:
        settings = dict(item.settings)
        if item.target_disposition not in {None, "CREATE", "REUSE", "BLOCK"}:
            raise ValueError("Invalid Check Point target disposition")
        if item.target_disposition == "REUSE" and not isinstance(settings.get("target_uid"), str):
            raise ValueError("Reused Management objects require a verified UID")
        if item.blockers or item.target_disposition == "BLOCK" or any(key in blocked for key in item.dependencies):
            blocked.add(item.key)
        operation = settings.get("management_operation")
        if operation is not None:
            if operation.get("path") not in _MANAGEMENT_PATHS:
                raise ValueError("Check Point plan contains an unverified Management API path")
            if operation.get("path") == "/web_api/set-access-layer":
                body = operation.get("request_body_template", {})
                packages = [row for row in plan.items if row.family == "package" and row.key in item.dependencies]
                if (plan.options.get("target_mode") != "new" or item.family != "layer" or len(packages) != 1
                        or body.get("uid") != {"$response_binding": packages[0].key + ".layer_uid"}):
                    raise ValueError("Layer configuration must refer only to this plan's newly created package layer")
            binding = operation.get("response_binding", {}).get("binding_id")
            if binding:
                if binding in bindings:
                    raise ValueError("Check Point plan contains a duplicate response binding")
                bindings[binding] = item.key
        for line in settings.get("gaia_commands", ()):
            low = line.strip().casefold()
            if not low.startswith(("set static-route ", "set ipv6 static-route ")):
                raise ValueError("Gaia export contains a command outside the verified static-route subset")
            if any(word in low for word in (" save config", " publish", " install-policy", " commit", " delete ")):
                raise ValueError("Gaia export contains a prohibited activation or destructive command")
    for item in ordered:
        operation = dict(item.settings).get("management_operation")
        if operation is None or item.key in blocked:
            continue
        allowed_dependencies = set(item.dependencies)
        for binding in _response_bindings(operation.get("request_body_template")):
            dependency = bindings.get(binding)
            if dependency is None or dependency not in allowed_dependencies:
                raise ValueError("Management API request references an unbound or undeclared UID dependency")
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


def dispositions(plan):
    validate_plan(plan)
    result = {}
    owners = defaultdict(list)
    for item in plan.items:
        if item.family in {"address", "address_group", "service", "service_group", "package"}:
            owners[item.target_name.casefold()].append(item.key)
    ambiguous = {key for keys in owners.values() if len(keys) > 1 for key in keys}
    for item in ordered_items(plan):
        blocked_dependency = any(result[dependency] == "BLOCK" for dependency in item.dependencies)
        result[item.key] = "BLOCK" if item.blockers or blocked_dependency or item.key in ambiguous else item.target_disposition or "CREATE"
    return result
