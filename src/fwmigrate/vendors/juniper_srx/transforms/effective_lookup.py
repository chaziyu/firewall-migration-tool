"""Read-only lookup of effective objects supplied by Junos groups."""


class EffectiveJunosLookup:
    def __init__(self, statements=()):
        self._objects = {}
        for item in statements:
            if item.get("origin") != "inherited-group" or item.get("status") != "EFFECTIVE":
                continue
            context = item.get("context", "root")
            path = tuple(item.get("target_path") or ())
            prefix = ("logical-systems", context.removeprefix("logical-system ")) if context.startswith("logical-system ") else (
                "tenants", context.removeprefix("tenant ")) if context.startswith("tenant ") else ()
            if prefix and path[:2] == prefix:
                path = path[2:]
            if path:
                self._objects.setdefault(context, set()).add(path)

    def contains(self, context, *paths):
        objects = self._objects.get(context, ())
        return any(any(candidate[:len(path)] == path for candidate in objects) for path in paths)
