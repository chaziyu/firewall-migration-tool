"""SRX plan validation and fail-closed dependency disposition."""

from dataclasses import replace

from .models import SRXFinding


def build_plan_dependency_index(items):
    return {item.key: tuple(item.dependencies) for item in items}


def _cycle_keys(index):
    visiting, visited, cycles = [], set(), set()

    def visit(key):
        if key in visiting:
            cycles.update(visiting[visiting.index(key):])
            return
        if key in visited:
            return
        visiting.append(key)
        for dependency in index.get(key, ()):
            if dependency in index:
                visit(dependency)
        visiting.pop()
        visited.add(key)

    for key in index:
        visit(key)
    return cycles


def validate_plan(plan):
    items = list(plan.items)
    findings = list(plan.findings)
    keys = [item.key for item in items]
    duplicate_keys = {key for key in keys if keys.count(key) > 1}
    target_owners = {}
    for item in items:
        if item.family != "interface":
            target_owners.setdefault((item.family, item.target_name.casefold()), []).append(item.key)
    duplicate_targets = {key for owners in target_owners.values() if len(owners) > 1 for key in owners}
    index = build_plan_dependency_index(items)
    cycles = _cycle_keys(index)
    known = set(index)
    validated = []
    for item in items:
        blockers = list(item.blockers)
        if item.target_disposition not in {None, "CREATE", "REUSE", "BLOCK"}:
            blockers.append("TARGET_DISPOSITION_INVALID")
        if item.key in duplicate_keys:
            blockers.append("DUPLICATE_PLAN_IDENTITY")
        if item.key in duplicate_targets:
            blockers.append("DUPLICATE_TARGET_OBJECT_NAME")
        if any(dependency not in known for dependency in item.dependencies):
            blockers.append("PLAN_DEPENDENCY_UNRESOLVED")
        if item.key in cycles:
            blockers.append("PLAN_DEPENDENCY_CYCLE")
        validated.append(replace(item, blockers=tuple(dict.fromkeys(blockers))))
    if duplicate_keys:
        findings.append(SRXFinding("DUPLICATE_PLAN_IDENTITY", "The plan contains duplicate item identities."))
    if duplicate_targets:
        findings.append(SRXFinding("DUPLICATE_TARGET_OBJECT_NAME", "The plan contains duplicate target names."))
    if any(any(dependency not in known for dependency in item.dependencies) for item in items):
        findings.append(SRXFinding("PLAN_DEPENDENCY_UNRESOLVED", "A planned item refers to a missing dependency."))
    if cycles:
        findings.append(SRXFinding("PLAN_DEPENDENCY_CYCLE", "The plan contains a dependency cycle."))
    return replace(plan, items=tuple(validated), findings=tuple(findings))


def assess_render_disposition(plan):
    dispositions = {
        item.key: ("BLOCK" if item.blockers else item.target_disposition or "CREATE")
        for item in plan.items
    }
    changed = True
    by_key = {item.key: item for item in plan.items}
    while changed:
        changed = False
        for key, disposition in tuple(dispositions.items()):
            if disposition in {"CREATE", "REUSE"} and any(
                dispositions.get(dependency) == "BLOCK" for dependency in by_key[key].dependencies
            ):
                dispositions[key] = "BLOCK"
                changed = True
    return dispositions
