"""Ancestor-aware PAN-OS XML traversal context."""

from __future__ import annotations

from dataclasses import dataclass, replace
import xml.etree.ElementTree as ET
from collections.abc import Iterator

from .source_model import PANScope


@dataclass(frozen=True)
class PANWalkContext:
    device_name: str | None = None
    device_serial: str | None = None
    vsys: str | None = None
    device_group: str | None = None
    parent_device_group: str | None = None
    scope: PANScope | None = None
    rulebase_position: str | None = None


def _serial(element: ET.Element) -> str | None:
    for attribute in ("serial", "serial-number", "serialnumber"):
        if element.get(attribute):
            return element.get(attribute)
    return None


def _transition(element: ET.Element, path: tuple[str, ...], parent: PANWalkContext) -> PANWalkContext:
    context = parent
    if element.tag == "shared":
        context = replace(context, scope=PANScope(kind="shared", name="shared"))

    parent_tag = path[-1] if path else None
    if element.tag == "entry" and parent_tag in {"devices", "device"}:
        if "device-group" in path:
            context = replace(context, device_serial=_serial(element) or element.get("name"))
        else:
            name = element.get("name")
            serial = _serial(element)
            context = replace(
                context,
                device_name=name,
                device_serial=serial,
                scope=PANScope(kind="device", name=name or "device", device_name=name, device_serial=serial),
            )

    if element.tag == "entry" and parent_tag == "device-group":
        name = element.get("name") or "device-group"
        parent_device_group = element.findtext("parent-dg")
        context = replace(
            context,
            device_group=name,
            parent_device_group=parent_device_group,
            scope=PANScope(
                kind="device-group",
                name=name,
                device_name=context.device_name,
                device_serial=context.device_serial,
                device_group=name,
                parent_device_group=parent_device_group,
            ),
        )

    if element.tag == "entry" and parent_tag == "vsys":
        name = element.get("name") or "vsys"
        context = replace(
            context,
            vsys=name,
            scope=PANScope(
                kind="vsys",
                name=name,
                device_name=context.device_name,
                device_serial=context.device_serial,
                vsys=name,
                device_group=context.device_group,
                parent_device_group=context.parent_device_group,
            ),
        )

    rulebase_position = {"pre-rulebase": "pre", "rulebase": "local", "post-rulebase": "post"}.get(element.tag)
    if rulebase_position is not None:
        context = replace(context, rulebase_position=rulebase_position)
    return context


def walk_pan_source(root: ET.Element) -> Iterator[tuple[ET.Element, tuple[str, ...], PANWalkContext]]:
    """Yield each XML element with context derived only from its ancestors."""

    def visit(element: ET.Element, path: tuple[str, ...], context: PANWalkContext):
        current_path = path + (element.tag,)
        current_context = _transition(element, path, context)
        yield element, current_path, current_context
        for child in element:
            yield from visit(child, current_path, current_context)

    yield from visit(root, (), PANWalkContext())
