"""Plan integrity checks shared by ASA review and rendering."""

import heapq
from collections import defaultdict


def ordered_items(plan, *, priority=lambda item: item.key):
    by_key = {item.key: item for item in plan.items}
    indegree = {item.key: len(set(item.dependencies)) for item in plan.items}
    dependents = defaultdict(list)
    for item in plan.items:
        for dependency in set(item.dependencies):
            if dependency not in by_key:
                raise ValueError("ASA migration plan contains an unresolved dependency")
            dependents[dependency].append(item.key)
    ready = [(priority(item), item.key) for item in plan.items if not indegree[item.key]]
    heapq.heapify(ready)
    result = []
    while ready:
        _, key = heapq.heappop(ready)
        result.append(by_key[key])
        for dependent in dependents[key]:
            indegree[dependent] -= 1
            if not indegree[dependent]:
                heapq.heappush(ready, (priority(by_key[dependent]), dependent))
    if len(result) != len(plan.items):
        raise ValueError("ASA migration plan contains a dependency cycle")
    return tuple(result)


def validate_plan(plan):
    keys = [item.key for item in plan.items]
    if len(keys) != len(set(keys)):
        raise ValueError("ASA migration plan contains duplicate item keys")
    for item in plan.items:
        for command in dict(item.settings).get("commands", ()):
            low = command.strip().casefold()
            if low.startswith(("write memory", "wr mem", "changeto ", "commit", "clear configure")):
                raise ValueError("ASA export contains a device operation")
    ordered_items(plan)
    return plan


def dispositions(plan):
    result = {}
    for item in ordered_items(plan):
        result[item.key] = "BLOCK" if item.blockers or any(result[dep] == "BLOCK" for dep in item.dependencies) else item.disposition
    return result
