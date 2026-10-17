"""Plan integrity checks shared by ASA review and rendering."""


def validate_plan(plan):
    keys = [item.key for item in plan.items]
    if len(keys) != len(set(keys)):
        raise ValueError("ASA migration plan contains duplicate item keys")
    known = set(keys)
    for item in plan.items:
        missing = set(item.dependencies) - known
        if missing:
            raise ValueError("ASA migration plan contains an unresolved dependency")
        for command in dict(item.settings).get("commands", ()):
            low = command.strip().casefold()
            if low.startswith(("write memory", "wr mem", "changeto ", "commit", "clear configure")):
                raise ValueError("ASA export contains a device operation")
    visiting, visited = set(), set()

    def visit(key):
        if key in visiting:
            raise ValueError("ASA migration plan contains a dependency cycle")
        if key in visited:
            return
        visiting.add(key)
        item = plan.items[keys.index(key)]
        for dependency in item.dependencies:
            visit(dependency)
        visiting.remove(key)
        visited.add(key)

    for key in keys:
        visit(key)
    return plan


def dispositions(plan):
    by_key = {item.key: item for item in plan.items}
    result = {}
    def assess(key):
        if key in result:
            return result[key]
        item = by_key[key]
        value = "BLOCK" if item.blockers or any(assess(dep) == "BLOCK" for dep in item.dependencies) else item.disposition
        result[key] = value
        return value
    for key in by_key:
        assess(key)
    return result
