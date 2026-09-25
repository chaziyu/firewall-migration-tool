from __future__ import annotations

from dataclasses import dataclass

from ..model import CiscoFTDInterface, CiscoFTDInterfaceSource


@dataclass(frozen=True)
class FTDInterfaceTopologyIssue:
    category: str
    message: str
    interface: str


@dataclass(frozen=True)
class FTDInterfaceTopologyEntry:
    name: str
    kind: str
    parent: str | None = None
    aggregate: str | None = None
    physical_interfaces: tuple[str, ...] = ()
    path: tuple[str, ...] = ()
    device_id: str | None = None


@dataclass(frozen=True)
class FTDInterfaceTopology:
    interfaces: tuple[FTDInterfaceTopologyEntry, ...] = ()
    issues: tuple[FTDInterfaceTopologyIssue, ...] = ()


def build_ftd_interface_topology(interfaces: list[CiscoFTDInterface | CiscoFTDInterfaceSource]) -> FTDInterfaceTopology:
    def key(interface, name=None):
        device_id = getattr(interface, "device_id", None) or getattr(interface, "source_attributes", {}).get("device_id")
        return (str(device_id or "").casefold(), str(name or interface.name).casefold())

    by_name = {key(interface): interface for interface in interfaces}
    issues: list[FTDInterfaceTopologyIssue] = []
    entries: list[FTDInterfaceTopologyEntry] = []
    for interface in interfaces:
        name = interface.name
        lowered = name.casefold()
        name_parent = name.rsplit(".", 1)[0] if "." in name else None
        parent = getattr(interface, "parent_interface", None) or name_parent
        aggregate = None
        if parent and (key(interface, parent) not in by_name):
            issues.append(FTDInterfaceTopologyIssue("missing-parent", f"Subinterface parent {parent} is missing", name))
        explicit_parent = getattr(interface, "parent_interface", None)
        if explicit_parent and name_parent and explicit_parent != name_parent:
            issues.append(FTDInterfaceTopologyIssue("conflicting-parent", "Explicit parent conflicts with name-derived parent", name))
        vlan_id = getattr(interface, "vlan_id", None)
        if parent and vlan_id is not None:
            suffix = name.rsplit(".", 1)[1]
            if suffix.isdigit() and int(suffix) != vlan_id:
                issues.append(FTDInterfaceTopologyIssue("vlan-evidence-conflict", f"Explicit VLAN {vlan_id} differs from subinterface suffix {suffix}", name))
        etherchannel_id = getattr(interface, "etherchannel_id", None)
        if etherchannel_id is not None:
            candidate = f"Port-channel{etherchannel_id}"
            if key(interface, candidate) in by_name:
                aggregate = by_name[key(interface, candidate)].name
            else:
                issues.append(FTDInterfaceTopologyIssue("missing-aggregate", f"Channel-group aggregate {candidate} is missing", name))
        interface_type = str(getattr(interface, "interface_type", "") or "").casefold()
        kind = ("subinterface" if parent else "etherchannel-member" if aggregate else
                "virtual-tunnel" if "tunnel" in interface_type else
                "vlan" if "vlan" in interface_type else
                "physical" if "physical" in interface_type else
                "bvi" if lowered.startswith("bvi") else
                "etherchannel" if lowered.startswith(("port-channel", "etherchannel")) else
                "management" if lowered.startswith("management") else
                "physical" if lowered.startswith(("gigabitethernet", "fastethernet", "ethernet", "tengigabitethernet")) else "logical")
        if aggregate:
            kind = "etherchannel-member"
        path = (parent, name) if parent else (name,)
        device_id = getattr(interface, "device_id", None) or getattr(interface, "source_attributes", {}).get("device_id")
        entries.append(FTDInterfaceTopologyEntry(name, kind, parent, aggregate, (), path, device_id))

    parents = {(str(entry.device_id or "").casefold(), entry.name.casefold()): entry.parent for entry in entries if entry.parent}
    reported_cycles: set[frozenset[str]] = set()
    for entry in entries:
        chain = [entry.name]
        seen = {entry.name.casefold()}
        current = entry.name
        scope = str(entry.device_id or "").casefold()
        while (scope, current.casefold()) in parents:
            current = parents[(scope, current.casefold())]
            if current.casefold() in seen:
                cycle = frozenset(name.casefold() for name in (*chain, current))
                if cycle not in reported_cycles:
                    issues.append(FTDInterfaceTopologyIssue("topology-cycle", "Interface parent relationships contain a cycle", entry.name))
                    reported_cycles.add(cycle)
                break
            chain.append(current)
            seen.add(current.casefold())

    aggregate_members: dict[tuple[str, str], list[str]] = {}
    for entry in entries:
        if entry.aggregate:
            aggregate_members.setdefault((str(entry.device_id or "").casefold(), entry.aggregate.casefold()), []).append(entry.name)
    entries = [FTDInterfaceTopologyEntry(
        item.name, item.kind, item.parent, item.aggregate,
        tuple(aggregate_members.get((str(item.device_id or "").casefold(), item.name.casefold()), ())), item.path, item.device_id,
    ) for item in entries]
    return FTDInterfaceTopology(tuple(entries), tuple(issues))
