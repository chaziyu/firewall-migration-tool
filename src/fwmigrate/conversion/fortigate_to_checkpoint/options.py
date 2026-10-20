"""Explicit Check Point management and Gaia target choices."""

from dataclasses import dataclass


def _text(value: str | None, label: str) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} must be a non-empty text value")
    return value.strip()


@dataclass(frozen=True, slots=True)
class CPMigrationOptions:
    source_vdom: str | None = None
    management_target: str | None = None
    management_domain: str | None = None
    management_api_version: str | None = None
    gaia_target: str | None = None
    policy_package: str | None = None
    access_layer: str | None = None
    install_on: tuple[str, ...] = ()
    insertion_anchor: str | None = None
    insertion_relation: str | None = None
    target_cleanup_action: str | None = None
    target_mode: str = "existing"

    def __post_init__(self) -> None:
        if self.target_mode not in {"new", "existing"}:
            raise ValueError("target_mode must be new or existing")
        for field in (
            "source_vdom", "management_target", "management_domain",
            "management_api_version", "gaia_target", "policy_package",
            "access_layer", "insertion_anchor", "insertion_relation",
            "target_cleanup_action",
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        if isinstance(self.install_on, str):
            values = (self.install_on,)
        elif isinstance(self.install_on, (tuple, list)):
            values = tuple(self.install_on)
        else:
            raise ValueError("install_on must be a list of explicit gateway or cluster names")
        values = tuple(_text(value, "install_on") for value in values)
        if len({value.casefold() for value in values}) != len(values):
            raise ValueError("install_on entries must be unique")
        object.__setattr__(self, "install_on", values)
        if self.insertion_relation not in {None, "above", "below"}:
            raise ValueError("insertion_relation must be above or below")
        if self.target_cleanup_action not in {None, "Drop"}:
            raise ValueError("target_cleanup_action must explicitly identify a Drop cleanup rule")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_vdom": self.source_vdom,
            "management_target": self.management_target,
            "management_domain": self.management_domain,
            "management_api_version": self.management_api_version,
            "gaia_target": self.gaia_target,
            "policy_package": self.policy_package,
            "access_layer": self.access_layer,
            "install_on": list(self.install_on),
            "insertion_anchor": self.insertion_anchor,
            "insertion_relation": self.insertion_relation,
            "target_cleanup_action": self.target_cleanup_action,
            "target_mode": self.target_mode,
        }

