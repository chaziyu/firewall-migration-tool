"""Juniper interface hierarchy and membership projection."""

from ..interface_topology import build_juniper_interface_topology


def build_interface_topology(context, scope: str) -> tuple[dict, ...]:
    return build_juniper_interface_topology(context, scope)
