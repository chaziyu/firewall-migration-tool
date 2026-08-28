import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRRoute
from fwmigrate.extraction.models import SourceInventoryItem, ExtractionStatus
from .source_model import PANScope

class PANRouteExtractor:
    @staticmethod
    def extract_static_routes(scope: PANScope, search_root: ET.Element, extraction):
        ir = extraction.canonical_ir
        # Allow routing extraction regardless of scope, as findall will naturally filter.
            
        # Parse IPv4 routes
        print("Searching virtual routers...", search_root.findall(".//virtual-router/entry"))
        for vr_entry in search_root.findall(".//virtual-router/entry"):
            print("Found vr_entry")
            vr_name = vr_entry.get("name") or "default"
            
            # IPv4
            for r_entry in vr_entry.findall("./routing-table/ip/static-route/entry"):
                r_name = r_entry.get("name") or "static-route"
                dest_elem = r_entry.find("destination")
                dest = dest_elem.text.strip() if dest_elem is not None and dest_elem.text else None
                
                if not dest:
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="routes",
                        source_path=f"virtual-router/entry[@name='{vr_name}']/routing-table/ip/static-route/entry[@name='{r_name}']",
                        name=r_name,
                        status=ExtractionStatus.PARTIALLY_NORMALIZED,
                        requires_manual_review=True,
                        notes=["IPv4 route missing required destination."]
                    ))
                    continue

                nh_elem = r_entry.find("./nexthop/ip-address")
                nh = nh_elem.text.strip() if nh_elem is not None and nh_elem.text else None

                intf_elem = r_entry.find("interface")
                intf = intf_elem.text.strip() if intf_elem is not None and intf_elem.text else None

                metric_elem = r_entry.find("metric")
                metric = int(metric_elem.text.strip()) if metric_elem is not None and metric_elem.text else 10

                ir.routes.append(IRRoute(
                    name=r_name,
                    destination=dest,
                    next_hop=nh,
                    interface=intf,
                    metric=metric
                ))

            # IPv6
            for r_entry in vr_entry.findall("./routing-table/ipv6/static-route/entry"):
                r_name = r_entry.get("name") or "static-route-v6"
                dest_elem = r_entry.find("destination")
                dest = dest_elem.text.strip() if dest_elem is not None and dest_elem.text else None
                
                if not dest:
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="routes",
                        source_path=f"virtual-router/entry[@name='{vr_name}']/routing-table/ipv6/static-route/entry[@name='{r_name}']",
                        name=r_name,
                        status=ExtractionStatus.PARTIALLY_NORMALIZED,
                        requires_manual_review=True,
                        notes=["IPv6 route missing required destination."]
                    ))
                    continue

                nh_elem = r_entry.find("./nexthop/ipv6-address")
                nh = nh_elem.text.strip() if nh_elem is not None and nh_elem.text else None

                intf_elem = r_entry.find("interface")
                intf = intf_elem.text.strip() if intf_elem is not None and intf_elem.text else None

                metric_elem = r_entry.find("metric")
                metric = int(metric_elem.text.strip()) if metric_elem is not None and metric_elem.text else 10

                route = IRRoute(
                    name=r_name,
                    destination=dest,
                    next_hop=nh,
                    interface=intf,
                    metric=metric
                )
                route.is_ipv6 = True
                ir.routes.append(route)
