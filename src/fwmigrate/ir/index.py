from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Tuple

from fwmigrate.ir.config import IRConfig


def _values(value: Any) -> Iterable[Any]:
    if isinstance(value, (list, tuple)):
        return value
    return ()


@dataclass(frozen=True)
class IRIndex:
    """Derived, read-only lookup maps for one canonical IR snapshot.

    Values are tuples because canonical names are not required to be unique.
    The index never changes the IR and must be rebuilt when the IR is replaced.
    """

    by_name: Mapping[str, Mapping[str, Tuple[Any, ...]]]
    by_id: Mapping[str, Mapping[str, Tuple[Any, ...]]]

    @classmethod
    def build(cls, ir: IRConfig) -> "IRIndex":
        names: Dict[str, Dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
        identifiers: Dict[str, Dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))

        for field_name in type(ir).model_fields:
            for item in _values(getattr(ir, field_name, None)):
                name = getattr(item, "name", None)
                if name is not None:
                    names[field_name][str(name)].append(item)
                for attribute in ("id", "uid", "source_uuid"):
                    identifier = getattr(item, attribute, None)
                    if identifier is not None:
                        identifiers[field_name][str(identifier)].append(item)

        return cls(
            by_name={field: {key: tuple(items) for key, items in values.items()} for field, values in names.items()},
            by_id={field: {key: tuple(items) for key, items in values.items()} for field, values in identifiers.items()},
        )

    def get_by_name(self, field_name: str, name: str) -> Tuple[Any, ...]:
        return self.by_name.get(field_name, {}).get(name, ())

    def get_by_id(self, field_name: str, identifier: str) -> Tuple[Any, ...]:
        return self.by_id.get(field_name, {}).get(identifier, ())

    def lookup(self, field_name: str, key: str) -> Tuple[Any, ...]:
        """Look up either a canonical name or an identifier."""
        return self.get_by_name(field_name, key) or self.get_by_id(field_name, key)

    @property
    def objects_by_name(self) -> Mapping[str, Mapping[str, Tuple[Any, ...]]]:
        return self.by_name

    @property
    def objects_by_id(self) -> Mapping[str, Mapping[str, Tuple[Any, ...]]]:
        return self.by_id


__all__ = ["IRIndex"]
