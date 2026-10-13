"""Read-only lookup of local and inherited effective Junos paths."""


class EffectiveJunosLookup:
    def __init__(self, statements=()):
        self._inherited = {}
        self._local = {}
        self._inactive = {}
        self.has_source = False
        for item in statements:
            self.has_source = True
            if item.get("origin") == "activation":
                self._inactive.setdefault(item.get("context", "root"), set()).add(
                    tuple(part.lower() for part in item.get("target_path") or ()))
            if item.get("status") != "EFFECTIVE":
                continue
            context = item.get("context", "root")
            path = tuple(part.lower() for part in item.get("target_path") or ())
            prefix = (("logical-systems", context.removeprefix("logical-system "))
                      if context.startswith("logical-system ") else
                      ("tenants", context.removeprefix("tenant "))
                      if context.startswith("tenant ") else ())
            prefix = tuple(part.lower() for part in prefix)
            if prefix and path[:2] == prefix:
                path = path[2:]
            elif context == "root" and path[:1] in (("logical-systems",), ("tenants",)):
                continue
            if path:
                index = self._inherited if item.get("origin") == "inherited-group" else self._local
                index.setdefault(context, set()).add(path)

    @staticmethod
    def _contains(paths, *targets):
        targets = (tuple(part.lower() for part in target) for target in targets)
        return any(path[:len(target)] == target for target in targets for path in paths)

    def contains(self, context, *paths):
        """Keep inherited-only semantics for existing callers."""
        return self._contains(self._inherited.get(context, ()), *paths)

    def contains_effective_path(self, context, *paths):
        return any(self._contains(index.get(context, ()), path)
                   and not self.hierarchy_is_inactive(context, path)
                   for index in (self._inherited, self._local) for path in paths)

    def path_is_effective(self, context, path):
        """Check one exact local or inherited source hierarchy path."""
        return self.contains_effective_path(context, path)

    def hierarchy_is_inactive(self, context, *paths):
        inactive = self._inactive.get(context, ())
        return any(tuple(part.lower() for part in target)[:len(prefix)] == prefix
                   for prefix in inactive for target in paths)

    def explicit_object_is_effective(self, context, path):
        path = tuple(part.lower() for part in path)
        return self._contains(self._local.get(context, ()), path) and not self.hierarchy_is_inactive(context, path)
