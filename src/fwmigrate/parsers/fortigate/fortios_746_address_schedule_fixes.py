"""FortiOS 7.4.6 address-template and schedule-group correctness fixes.

This extension is deliberately narrow:
- model ``firewall address6-template`` using the documented 7.4.6 hierarchy;
- register context-scoped ``firewall address6 -> address6-template`` dependencies;
- keep schedule-group source metadata and reject nested schedule groups as members.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, SerializeAsAny, model_validator

from fwmigrate.parsers.fortigate import model as model_module
from fwmigrate.parsers.fortigate.model import FGContextualModel, _preserve_malformed_int_fields


class FGAddress6TemplateValue746(BaseModel):
    """One value entry beneath an address6-template subnet segment."""

    source_id: str
    value: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddress6TemplateSegment746(BaseModel):
    """One ``config subnet-segment`` entry from FortiOS 7.4.6."""

    source_id: str
    bits: Optional[int] = None
    exclusive: Optional[str] = None
    name: Optional[str] = None
    values: List[FGAddress6TemplateValue746] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_bits(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"bits"})


class FGAddress6Template746(FGContextualModel):
    """Typed FortiOS 7.4.6 ``firewall address6-template`` inventory."""

    name: str
    ip6: Optional[str] = None
    subnet_segment_count: Optional[int] = None
    fabric_object: Optional[str] = None
    subnet_segments: List[FGAddress6TemplateSegment746] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_count(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"subnet_segment_count"})

    @model_validator(mode="after")
    def _project_subnet_segments(self) -> "FGAddress6Template746":
        if self.subnet_segments:
            return self

        self.subnet_segments = _parse_subnet_segments(self.nested_configs)
        return self


def _command_settings(node: Any) -> Dict[str, Any]:
    settings: Dict[str, Any] = {}
    for command in getattr(node, "commands", []):
        key = str(command.key).replace("-", "_")
        values = list(command.values)
        value: Any = values[0] if len(values) == 1 else values
        if command.operation == "unset":
            settings.pop(key, None)
            continue
        settings[key] = value
    return settings


def _parse_template_value(node: Any) -> FGAddress6TemplateValue746:
    settings = _command_settings(node)
    raw_value = settings.pop("value", None)
    value = None if raw_value is None else str(raw_value)
    return FGAddress6TemplateValue746(
        source_id=str(node.name),
        value=value,
        extra_settings=settings,
    )


def _parse_template_segment(node: Any) -> FGAddress6TemplateSegment746:
    settings = _command_settings(node)
    values: List[FGAddress6TemplateValue746] = []

    for child in getattr(node, "children", []):
        child_name = str(child.name).lower().replace("_", "-")
        if child.node_type != "config" or child_name != "values":
            continue
        values.extend(
            _parse_template_value(entry)
            for entry in child.children
            if entry.node_type == "edit"
        )

    typed: Dict[str, Any] = {
        "source_id": str(node.name),
        "bits": settings.pop("bits", None),
        "exclusive": settings.pop("exclusive", None),
        "name": settings.pop("name", None),
        "values": values,
        "extra_settings": settings,
    }
    return FGAddress6TemplateSegment746(**typed)


def _parse_subnet_segments(nodes: List[Any]) -> List[FGAddress6TemplateSegment746]:
    segments: List[FGAddress6TemplateSegment746] = []
    for node in nodes:
        node_name = str(node.name).lower().replace("_", "-")
        if node.node_type != "config" or node_name != "subnet-segment":
            continue
        segments.extend(
            _parse_template_segment(entry)
            for entry in node.children
            if entry.node_type == "edit"
        )
    return segments


def install_fortios_746_address_schedule_fixes(
    parser_module: Any,
    transformer_module: Any,
    dependencies_module: Any,
) -> None:
    """Install only the audited FortiOS 7.4.6 address/schedule corrections."""

    # This installer runs after the final root-model composition so it extends
    # the actual active FGConfig rather than an earlier phase's root model.
    active_root = parser_module.FGConfig

    class FGConfigAddressSchedule746(active_root):
        address6_templates: List[SerializeAsAny[FGAddress6Template746]] = Field(
            default_factory=list
        )

    model_module.FGAddress6Template = FGAddress6Template746
    model_module.FGConfig = FGConfigAddressSchedule746
    parser_module.FGAddress6Template = FGAddress6Template746
    parser_module.FGConfig = FGConfigAddressSchedule746

    dependencies_module.REFERENCE_RULES[(
        "firewall address6",
        "template",
    )] = "firewall address6-template"
    dependencies_module.REFERENCE_TARGET_SECTIONS[(
        "firewall address6",
        "template",
    )] = {"firewall address6-template"}

    transformer_cls = transformer_module.FGToIRTransformer
    if getattr(
        transformer_cls._transform_schedule_groups,
        "_fortios_746_address_schedule_fixed",
        False,
    ):
        return

    def _transform_schedule_groups(self: Any) -> None:
        schedules = {
            (item.source_context, item.name)
            for item in self.fg.schedules
        }
        for group in self.fg.schedule_groups:
            unresolved = [
                member
                for member in group.member
                if (group.source_context, member) not in schedules
            ]
            source_attributes = dict(group.extra_settings)
            source_color = getattr(group, "color", None)
            source_fabric_object = getattr(group, "fabric_object", None)
            if source_color is not None:
                source_attributes["color"] = source_color
            if source_fabric_object is not None:
                source_attributes["fabric_object"] = source_fabric_object

            self.ir.schedule_groups.append(
                transformer_module.IRScheduleGroup(
                    name=group.name,
                    source_context=group.source_context,
                    members=list(group.member),
                    description=group.comments,
                    unresolved_members=unresolved,
                    requires_manual_review=bool(unresolved),
                    source_attributes=source_attributes,
                )
            )

    _transform_schedule_groups._fortios_746_address_schedule_fixed = True
    transformer_cls._transform_schedule_groups = _transform_schedule_groups
