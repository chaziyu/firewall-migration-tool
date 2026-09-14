"""FortiOS 7.4.6 address and schedule correctness fixes.

This extension is deliberately narrow:
- apply documented effective address defaults without inventing source configuration;
- model ``firewall address6-template`` and preserve it in canonical IR;
- preserve multi-value ``fsso-group`` boundaries end to end;
- register context-scoped address-template dependencies;
- resolve documented FortiOS predefined service groups;
- keep schedule-group source metadata and reject nested schedule groups as members.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, SerializeAsAny, model_validator

from fwmigrate.ir.address import IRAddress as _IRAddress
from fwmigrate.ir import IRConfig as _IRConfig
from fwmigrate.parsers.fortigate import model as model_module
from fwmigrate.parsers.fortigate.model import (
    FGAddress as _FGAddress,
    FGContextualModel,
    _preserve_malformed_int_fields,
)
from fwmigrate.parsers.fortigate.predefined_services import is_predefined_service_group


class FGAddress746(_FGAddress):
    """Address model with section-specific FortiOS defaults applied by the parser."""

    type: Optional[str] = None
    fsso_group: List[str] = Field(default_factory=list)
    source_effective_defaults: Dict[str, Any] = Field(default_factory=dict)


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


class IRAddress6TemplateValue746(BaseModel):
    """Canonical source-preserving address6-template value entry."""

    source_id: str
    value: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAddress6TemplateSegment746(BaseModel):
    """Canonical source-preserving address6-template subnet segment."""

    source_id: str
    bits: Optional[int] = None
    exclusive: Optional[str] = None
    name: Optional[str] = None
    values: List[IRAddress6TemplateValue746] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAddress6Template746(BaseModel):
    """Canonical FortiGate IPv6 template inventory without target-side expansion."""

    name: str
    source_context: Optional[str] = None
    ip6: Optional[str] = None
    subnet_segment_count: Optional[int] = None
    subnet_segments: List[IRAddress6TemplateSegment746] = Field(default_factory=list)
    source_fabric_object: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAddress746(_IRAddress):
    """IR address fields required for exact FortiOS 7.4.6 source semantics."""

    source_fsso_group: List[str] = Field(default_factory=list)
    source_effective_defaults: Dict[str, Any] = Field(default_factory=dict)
    source_template: Optional[str] = None
    source_template_reference_resolved: Optional[bool] = None


class IRConfig746(_IRConfig):
    """IR root extended with source-preserving FortiGate IPv6 templates."""

    addresses: List[SerializeAsAny[IRAddress746]] = Field(default_factory=list)
    address6_templates: List[SerializeAsAny[IRAddress6Template746]] = Field(
        default_factory=list
    )


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


def _set_effective_default(
    attributes: Dict[str, Any],
    defaults: Dict[str, Any],
    key: str,
    value: Any,
) -> None:
    if key in attributes:
        return
    attributes[key] = value
    defaults[key] = value


def _apply_address_defaults(section_path: str, attributes: Dict[str, Any]) -> None:
    defaults = dict(attributes.get("source_effective_defaults") or {})

    if section_path == "firewall address":
        _set_effective_default(attributes, defaults, "type", "ipmask")
        if attributes.get("type") == "ipmask":
            _set_effective_default(
                attributes,
                defaults,
                "subnet",
                "0.0.0.0 0.0.0.0",
            )

    elif section_path == "firewall address6":
        _set_effective_default(attributes, defaults, "type", "ipprefix")
        if attributes.get("type") == "ipprefix":
            _set_effective_default(attributes, defaults, "ip6", "::/0")

    elif section_path == "firewall multicast-address":
        _set_effective_default(attributes, defaults, "type", "multicastrange")
        if attributes.get("type") == "multicastrange":
            _set_effective_default(attributes, defaults, "start_ip", "0.0.0.0")
            _set_effective_default(attributes, defaults, "end_ip", "0.0.0.0")
        elif attributes.get("type") == "broadcastmask":
            _set_effective_default(
                attributes,
                defaults,
                "subnet",
                "0.0.0.0 0.0.0.0",
            )

    elif section_path == "firewall multicast-address6":
        _set_effective_default(attributes, defaults, "ip6", "::/0")

    if defaults:
        attributes["source_effective_defaults"] = defaults


def _canonical_address6_template(source: Any) -> IRAddress6Template746:
    segments = [
        IRAddress6TemplateSegment746(
            source_id=segment.source_id,
            bits=segment.bits,
            exclusive=segment.exclusive,
            name=segment.name,
            values=[
                IRAddress6TemplateValue746(
                    source_id=value.source_id,
                    value=value.value,
                    source_attributes=dict(value.extra_settings),
                )
                for value in segment.values
            ],
            source_attributes=dict(segment.extra_settings),
        )
        for segment in source.subnet_segments
    ]
    review_reasons = [
        (
            "FortiGate address6-template is retained as canonical source "
            "inventory and is not expanded into concrete IPv6 addresses."
        )
    ]
    if (
        source.subnet_segment_count is not None
        and source.subnet_segment_count != len(segments)
    ):
        review_reasons.append(
            "Declared subnet-segment-count "
            f"{source.subnet_segment_count} does not match parsed segment count "
            f"{len(segments)}."
        )

    return IRAddress6Template746(
        name=source.name,
        source_context=source.source_context,
        ip6=source.ip6,
        subnet_segment_count=source.subnet_segment_count,
        subnet_segments=segments,
        source_fabric_object=source.fabric_object,
        review_reasons=review_reasons,
        source_attributes=dict(source.extra_settings),
    )


def _is_predefined_service_group_reference(record: Any) -> bool:
    if record.result != "UNRESOLVED":
        return False
    if not is_predefined_service_group(record.reference):
        return False
    return (
        record.source_path == "firewall service group"
        and record.source_field == "member"
    ) or (
        record.source_field == "service"
        and record.source_path
        in {
            "firewall policy",
            "firewall local-in-policy",
            "firewall local-in-policy6",
            "firewall security-policy",
            "firewall DoS-policy",
            "firewall DoS-policy6",
        }
    )


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
        addresses: List[SerializeAsAny[FGAddress746]] = Field(default_factory=list)
        address6_templates: List[SerializeAsAny[FGAddress6Template746]] = Field(
            default_factory=list
        )

    model_module.FGAddress = FGAddress746
    model_module.FGAddress6Template = FGAddress6Template746
    model_module.FGConfig = FGConfigAddressSchedule746
    parser_module.FGAddress = FGAddress746
    parser_module.FGAddress6Template = FGAddress6Template746
    parser_module.FGConfig = FGConfigAddressSchedule746
    parser_module.SECTION_LIST_FIELDS.setdefault("firewall address", set()).add(
        "fsso_group"
    )

    transformer_module.IRAddress = IRAddress746
    transformer_module.IRConfig = IRConfig746

    dependencies_module.REFERENCE_RULES[(
        "firewall address6",
        "template",
    )] = "firewall address6-template"
    dependencies_module.REFERENCE_TARGET_SECTIONS[(
        "firewall address6",
        "template",
    )] = {"firewall address6-template"}

    parser_cls = parser_module.FortiGateParser
    if not getattr(
        parser_cls.build_model,
        "_fortios_746_address_defaults_fixed",
        False,
    ):
        original_build_model = parser_cls.build_model

        def build_model(
            self: Any,
            section_path: str,
            attributes: Dict[str, Any],
        ) -> Any:
            if section_path in {
                "firewall address",
                "firewall address6",
                "firewall multicast-address",
                "firewall multicast-address6",
            }:
                _apply_address_defaults(section_path, attributes)
            return original_build_model(self, section_path, attributes)

        build_model._fortios_746_address_defaults_fixed = True
        parser_cls.build_model = build_model

    transformer_cls = transformer_module.FGToIRTransformer

    if not getattr(
        transformer_cls._address_source_attributes,
        "_fortios_746_address_defaults_fixed",
        False,
    ):
        original_address_source_attributes = transformer_cls._address_source_attributes

        def _address_source_attributes(addr: Any) -> Dict[str, object]:
            source_attributes = original_address_source_attributes(addr)
            defaults = dict(getattr(addr, "source_effective_defaults", {}) or {})
            for key in defaults:
                source_attributes.pop(key, None)
            if not getattr(addr, "fsso_group", None):
                source_attributes.pop("fsso_group", None)
            else:
                source_attributes["fsso_group"] = list(addr.fsso_group)
            return source_attributes

        _address_source_attributes._fortios_746_address_defaults_fixed = True
        transformer_cls._address_source_attributes = staticmethod(
            _address_source_attributes
        )

    if not getattr(
        transformer_cls._transform_addresses,
        "_fortios_746_address_defaults_fixed",
        False,
    ):
        original_transform_addresses = transformer_cls._transform_addresses

        def _transform_addresses(self: Any) -> None:
            original_transform_addresses(self)

            self.ir.address6_templates.extend(
                _canonical_address6_template(template)
                for template in self.fg.address6_templates
            )

            template_keys = {
                (template.source_context, template.name)
                for template in self.fg.address6_templates
            }
            source_by_key = {
                (address.source_context, address.name): address
                for address in self.fg.addresses
            }
            for address in self.ir.addresses:
                source = source_by_key.get(
                    (address.source_context, address.name)
                )
                if source is None:
                    continue

                defaults = dict(
                    getattr(source, "source_effective_defaults", {}) or {}
                )
                if defaults:
                    attributes = dict(address.source_attributes)
                    for key in defaults:
                        attributes.pop(key, None)
                    address.source_attributes = attributes
                    address.source_effective_defaults = defaults

                template_name = getattr(source, "template", None)
                if not template_name:
                    continue
                resolved = (
                    source.source_context,
                    template_name,
                ) in template_keys
                address.source_template = template_name
                address.source_template_reference_resolved = resolved
                attributes = dict(address.source_attributes)
                attributes["template_reference_resolved"] = resolved
                address.source_attributes = attributes
                if not resolved:
                    address.requires_manual_review = True
                    address.migration_status = "PARTIALLY_NORMALIZED"
                    reason = (
                        f"FortiGate IPv6 template reference {template_name!r} "
                        "was not found in the same source context."
                    )
                    address.audit_note = "; ".join(
                        part
                        for part in (address.audit_note, reason)
                        if part
                    )

        _transform_addresses._fortios_746_address_defaults_fixed = True
        transformer_cls._transform_addresses = _transform_addresses

    if not getattr(
        transformer_cls._transform_schedule_groups,
        "_fortios_746_address_schedule_fixed",
        False,
    ):
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

    if not getattr(
        dependencies_module.build_dependency_registry,
        "_fortios_746_predefined_service_groups_fixed",
        False,
    ):
        original_build_dependency_registry = (
            dependencies_module.build_dependency_registry
        )

        def build_dependency_registry(items: Any) -> Any:
            records = original_build_dependency_registry(items)
            return [
                record.model_copy(
                    update={
                        "result": "RESOLVED",
                        "target_path": "fortigate predefined service group",
                        "notes": (
                            "Resolved against the documented FortiOS 7.4 "
                            "predefined service-group inventory."
                        ),
                    }
                )
                if _is_predefined_service_group_reference(record)
                else record
                for record in records
            ]

        build_dependency_registry._fortios_746_predefined_service_groups_fixed = True
        dependencies_module.build_dependency_registry = build_dependency_registry

        extractor_module = sys.modules.get(
            "fwmigrate.parsers.fortigate.extractor"
        )
        if extractor_module is not None:
            extractor_module.build_dependency_registry = build_dependency_registry

    extractor_module = sys.modules.get(
        "fwmigrate.parsers.fortigate.extractor"
    )
    if extractor_module is not None:
        extractor_module.SOURCE_ONLY_OPERATIONAL_SECTIONS.add(
            "firewall address6-template"
        )
