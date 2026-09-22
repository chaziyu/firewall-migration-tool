from __future__ import annotations

from .fdm_bundle import (
    CiscoFDMBundleParser as _RawCiscoFDMBundleParser,
    FDM_BUNDLE_FORMAT,
    _items,
    is_fdm_bundle,
)
from ..model import (
    CiscoFTDACPRule, CiscoFTDConfig, CiscoFTDInterfaceSource,
    CiscoFTDNATRule, CiscoFTDObject, CiscoFTDRoute, CiscoFTDService,
    CiscoFTDZone,
)


class CiscoFDMBundleParser(_RawCiscoFDMBundleParser):
    """Apply fail-closed generation gates to the structured FDM parser."""

    def parse(self):
        from ..transformer import FDMToIRTransformer

        return FDMToIRTransformer(self).transform()

    def parse_source(self) -> CiscoFTDConfig:
        """Build FTD source state directly from the FDM REST payload."""
        plane = "fdm-rest-bundle"

        def items(*names: str) -> list[dict]:
            return self._collection(*names)

        def record(item: dict, index: int, cls, **values):
            return cls(
                name=str(item.get("name") or item.get("id") or index),
                source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, raw=item,
                source_attributes={"provenance": "FDM REST", "domain_id": self.domain_id},
                **values,
            )

        object_groups = [record(item, i, CiscoFTDObject, object_type="network-group",
                                members=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                         for x in item.get("objects", item.get("members", []))])
                         for i, item in enumerate(items("network_groups", "networkgroups"), 1)]
        managed = [record(item, i, CiscoFTDObject, object_type=kind)
                   for kind, names in (("network", ("hosts", "network_hosts", "networks", "network_objects", "ranges", "network_ranges")),)
                   for collection_name in names for i, item in enumerate(items(collection_name), 1)]
        services = [record(item, i, CiscoFTDService, protocol=item.get("protocol"), ports=item.get("ports", []))
                    for i, item in enumerate(items("services", "service_objects"), 1)]
        services += [record(item, i, CiscoFTDService, protocol=item.get("protocol"),
                            members=[str(x.get("name") or x.get("id") or x) if isinstance(x, dict) else str(x)
                                     for x in item.get("objects", item.get("members", []))])
                     for i, item in enumerate(items("service_groups", "servicegroups"), 1)]
        zones = [record(item, i, CiscoFTDZone, interfaces=item.get("interfaces", []))
                 for i, item in enumerate(items("zones", "security_zones"), 1)]
        interfaces = [record(item, i, CiscoFTDInterfaceSource,
                             interface_type=item.get("type"), address=item.get("address"),
                             zone=item.get("zone"))
                      for i, item in enumerate(items("interfaces"), 1)]
        routes = [record(item, i, CiscoFTDRoute, interface=item.get("interface"),
                         destination=item.get("destination"), gateway=item.get("gateway"))
                  for i, item in enumerate(items("routes", "static_routes"), 1)]
        nat_rules = []
        for i, item in enumerate(self._nat_rules(), 1):
            nat_rules.append(record(item, i, CiscoFTDNATRule,
                policy=str(item.get("policy") or item.get("policyName") or "default"),
                source_interface=item.get("sourceInterface"),
                destination_interface=item.get("destinationInterface"),
                original=item.get("original", {}), translated=item.get("translated", {}), order=i))
        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={"domain_id": self.domain_id, "domain_name": self.domain_name,
                             "source": self.payload.get("source", "fdm-rest-api")},
            managed_objects=managed, object_groups=object_groups, services=services,
            security_zones=zones, source_interfaces=interfaces, routes=routes,
            nat_policies=nat_rules,
            unsupported_evidence=[] if nat_rules else [{"source_path": "fdm/nat-policies", "reason": "No NAT policy data in FDM bundle"}],
        )


__all__ = ["CiscoFDMBundleParser", "FDM_BUNDLE_FORMAT", "is_fdm_bundle"]
