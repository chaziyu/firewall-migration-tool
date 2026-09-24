from __future__ import annotations

from dataclasses import dataclass

from ..model import CiscoFTDInterface


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


@dataclass(frozen=True)
class FTDInterfaceTopology:
    interfaces: tuple[FTDInterfaceTopologyEntry, ...] = ()
    issues: tuple[FTDInterfaceTopologyIssue, ...] = ()


def build_ftd_interface_topology(interfaces: list[CiscoFTDInterface]) -> FTDInterfaceTopology:
    by_name = {interface.name.casefold(): interface for interface in interfaces}
    issues: list[FTDInterfaceTopologyIssue] = []
    entries: list[FTDInterfaceTopologyEntry] = []
    for interface in interfaces:
        name = interface.name
        lowered = name.casefold()
        name_parent = name.rsplit(".", 1)[0] if "." in name else None
        parent = interface.parent_interface or name_parent
        aggregate = None
        if parent and parent.casefold() not in by_name:
            issues.append(FTDInterfaceTopologyIssue("missing-parent", f"Subinterface parent {parent} is missing", name))
        if interface.parent_interface and name_parent and interface.parent_interface != name_parent:
            issues.append(FTDInterfaceTopologyIssue("conflicting-parent", "Explicit parent conflicts with name-derived parent", name))
        if parent and interface.vlan_id is not None:
            suffix = name.rsplit(".", 1)[1]
            if suffix.isdigit() and int(suffix) != interface.vlan_id:
                issues.append(FTDInterfaceTopologyIssue("vlan-evidence-conflict", f"Explicit VLAN {interface.vlan_id} differs from subinterface suffix {suffix}", name))
        if interface.etherchannel_id is not None:
            candidate = f"Port-channel{interface.etherchannel_id}"
            if candidate.casefold() in by_name:
                aggregate = by_name[candidate.casefold()].name
            else:
                issues.append(FTDInterfaceTopologyIssue("missing-aggregate", f"Channel-group aggregate {candidate} is missing", name))
        kind = ("subinterface" if parent else "etherchannel-member" if aggregate else
                "bvi" if lowered.startswith("bvi") else
                "etherchannel" if lowered.startswith(("port-channel", "etherchannel")) else
                "management" if lowered.startswith("management") else
                "physical" if lowered.startswith(("gigabitethernet", "fastethernet", "ethernet", "tengigabitethernet")) else "logical")
        if aggregate:
            kind = "etherchannel-member"
        path = (parent, name) if parent else (name,)
        entries.append(FTDInterfaceTopologyEntry(name, kind, parent, aggregate, (), path))

    parents = {entry.name.casefold(): entry.parent for entry in entries if entry.parent}
    reported_cycles: set[frozenset[str]] = set()
    for entry in entries:
        chain = [entry.name]
        seen = {entry.name.casefold()}
        current = entry.name
        while current.casefold() in parents:
            current = parents[current.casefold()]
            if current.casefold() in seen:
                cycle = frozenset(name.casefold() for name in (*chain, current))
                if cycle not in reported_cycles:
                    issues.append(FTDInterfaceTopologyIssue("topology-cycle", "Interface parent relationships contain a cycle", entry.name))
                    reported_cycles.add(cycle)
                break
            chain.append(current)
            seen.add(current.casefold())

    aggregate_members: dict[str, list[str]] = {}
    for entry in entries:
        if entry.aggregate:
            aggregate_members.setdefault(entry.aggregate.casefold(), []).append(entry.name)
    entries = [FTDInterfaceTopologyEntry(
        item.name, item.kind, item.parent, item.aggregate,
        tuple(aggregate_members.get(item.name.casefold(), ())), item.path,
    ) for item in entries]
    return FTDInterfaceTopology(tuple(entries), tuple(issues))
