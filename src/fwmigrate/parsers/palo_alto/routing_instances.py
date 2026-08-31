"""PAN-OS routing-instance discovery.

PAN-OS has two materially different routing hierarchies.  Keeping discovery
in one small module lets static and dynamic routing use the same identity and
source-path rules without duplicating vendor-specific traversal logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class PANRoutingInstance:
    """A legacy virtual router or a logical-router VRF source context."""

    instance_type: str
    virtual_router_name: Optional[str] = None
    logical_router_name: Optional[str] = None
    vrf_name: Optional[str] = None
    source_path: Optional[str] = None
    node: Optional[ET.Element] = None

    @property
    def display_name(self) -> str:
        if self.instance_type == "virtual-router":
            return self.virtual_router_name or "<unnamed>"
        logical = self.logical_router_name or "<unnamed>"
        return f"{logical}/{self.vrf_name or '<unnamed-vrf>'}"

    @property
    def context_attributes(self) -> dict:
        return {
            "routing_instance_type": self.instance_type,
            "virtual_router_name": self.virtual_router_name,
            "logical_router_name": self.logical_router_name,
            "vrf_name": self.vrf_name,
            "routing_instance_name": self.display_name,
        }

    def protocol_node(self) -> tuple[Optional[ET.Element], Optional[str]]:
        """Return the protocol container and its relative source label.

        PAN-OS releases and export shapes use both ``protocol`` and
        ``routing-protocol`` below a logical-router VRF.  We accept either,
        but never search unrelated descendants.
        """
        if self.node is None:
            return None, None
        for tag in ("protocol", "routing-protocol"):
            candidate = self.node.find(f"./{tag}")
            if candidate is not None:
                return candidate, tag
        return None, None


def discover_routing_instances(network_root: ET.Element) -> Iterator[PANRoutingInstance]:
    """Yield routing instances in deterministic PAN-OS source order.

    Valid advanced routing is rooted at
    ``network/logical-router/entry/vrf/entry``.  A direct logical-router
    protocol container is retained as a compatibility instance for older
    synthetic/export variants; valid logical-router VRFs always use the
    constrained ``logical-router-vrf`` type.
    """
    for entry in network_root.findall("./virtual-router/entry"):
        name = entry.get("name")
        path = f"network/virtual-router/entry[@name='{name}']"
        yield PANRoutingInstance(
            instance_type="virtual-router",
            virtual_router_name=name,
            source_path=path,
            node=entry,
        )

    for logical in network_root.findall("./logical-router/entry"):
        logical_name = logical.get("name")
        logical_path = f"network/logical-router/entry[@name='{logical_name}']"
        vrfs = logical.findall("./vrf/entry")
        for vrf in vrfs:
            vrf_name = vrf.get("name")
            yield PANRoutingInstance(
                instance_type="logical-router-vrf",
                logical_router_name=logical_name,
                vrf_name=vrf_name,
                source_path=f"{logical_path}/vrf/entry[@name='{vrf_name}']",
                node=vrf,
            )

        # Some historical exports put a protocol container directly below
        # logical-router.  Keep it visible for backward compatibility while
        # avoiding any claim that it is a real VRF hierarchy.
        if not vrfs and (logical.find("./protocol") is not None or
                         logical.find("./routing-protocol") is not None):
            yield PANRoutingInstance(
                instance_type="logical-router",
                logical_router_name=logical_name,
                source_path=logical_path,
                node=logical,
            )


def interface_members(instance: PANRoutingInstance) -> list[str]:
    """Return direct interface members for one PAN-OS routing instance.

    Interface membership is represented directly below a virtual-router or
    logical-router/VRF node.  Keep this traversal deliberately constrained so
    protocol interface references and other descendant ``member`` nodes are
    not mistaken for routing-instance membership.
    """
    if instance.node is None:
        return []

    members: list[str] = []
    for member in instance.node.findall("./interface/member"):
        name = (member.text or "").strip()
        if name and name not in members:
            members.append(name)
    return members


def static_route_entries(instance: PANRoutingInstance, family: str) -> tuple[str, list[ET.Element]]:
    """Return a route path label and entries for one address family."""
    if instance.node is None:
        return "", []
    family_node = "ip" if family == "ipv4" else "ipv6"
    relative = f"./routing-table/{family_node}/static-route/entry"
    return relative, instance.node.findall(relative)
