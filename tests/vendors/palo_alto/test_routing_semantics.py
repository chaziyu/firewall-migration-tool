from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_router_kind_route_fields_and_missing_values_are_source_faithful():
    config = build_panos_config("""<config><shared><network>
      <virtual-router><entry name='vr-main'><routing-table><ip><static-route>
        <entry name='default'><destination>0.0.0.0/0</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop><interface>ethernet1/1</interface><metric>10</metric></entry>
      </static-route></ip></routing-table></entry></virtual-router>
      <logical-router><entry name='lr-main'><vrf><entry name='production'><routing-table><ip><static-route>
        <entry name='branch'><destination>10.0.0.0/8</destination><nexthop><discard/></nexthop><path-monitor><enable>yes</enable><monitor-destinations><entry name='probe'><destination>192.0.2.2</destination></entry></monitor-destinations></path-monitor><future-route-leaf>keep</future-route-leaf></entry>
      </static-route></ip></routing-table></entry></vrf></entry></logical-router>
    </network></shared></config>""")

    virtual_router = config.virtual_routers[0]
    logical_router = config.logical_routers[0]
    vr_route = virtual_router.static_routes[0]
    lr_route = logical_router.vrfs[0].static_routes[0]
    assert virtual_router.name == "vr-main" and logical_router.name == "lr-main"
    assert vr_route.name == "default" and vr_route.address_family == "ipv4"
    assert (vr_route.destination, vr_route.nexthop_type, vr_route.nexthop_ip_address, vr_route.interface, vr_route.metric) == (
        "0.0.0.0/0", "ip-address", "192.0.2.1", "ethernet1/1", "10"
    )
    assert lr_route.name == "branch" and logical_router.vrfs[0].name == "production"
    assert (lr_route.address_family, lr_route.destination, lr_route.nexthop_type) == ("ipv4", "10.0.0.0/8", "discard")
    assert (lr_route.interface, lr_route.metric, lr_route.path_monitor.targets[0].destination) == (None, None, "192.0.2.2")
    assert lr_route.raw_extra["future-route-leaf"] == "keep"
    assert vr_route.metric is not None and vr_route.path_monitor is None
    assert (vr_route.router_type, vr_route.router_name, vr_route.vrf_name) == ("virtual-router", "vr-main", None)
    assert (lr_route.router_type, lr_route.router_name, lr_route.vrf_name) == ("logical-router", "lr-main", "production")
    assert "static_routes" not in type(config).model_fields
    assert [route.name for route in build_derived_views(config).static_routes] == ["default", "branch"]


def test_ipv6_static_routes_are_typed_with_inventory_order_and_without_duplicate_raw_routing_table():
    config = build_panos_config("""<config><shared><network>
      <virtual-router><entry name='vr-main'><routing-table>
        <ip><static-route><entry name='v4-route'><destination>192.0.2.0/24</destination></entry></static-route></ip>
        <ipv6><static-route><entry name='v6-route'><destination>2001:db8::/32</destination><nexthop><ip-address>2001:db8::1</ip-address></nexthop></entry></static-route></ipv6>
      </routing-table></entry></virtual-router>
      <logical-router><entry name='lr-main'><vrf><entry name='blue'><routing-table><ipv6><static-route>
        <entry name='lr-v6'><destination>2001:db8:1::/48</destination><nexthop><discard/></nexthop></entry>
      </static-route></ipv6></routing-table></entry></vrf></entry></logical-router>
    </network></shared></config>""")

    vr = config.virtual_routers[0]
    lr = config.logical_routers[0]
    assert [(route.name, route.address_family) for route in vr.static_routes] == [
        ("v4-route", "ipv4"), ("v6-route", "ipv6")
    ]
    assert lr.vrfs[0].static_routes[0].address_family == "ipv6"
    assert vr.static_routes[1].nexthop_ip_address == "2001:db8::1"
    assert "routing-table" not in vr.raw_extra

    inventory_order = {record.name: record.source_order for record in config.source_inventory}
    assert vr.static_routes[0].source_order == inventory_order["v4-route"]
    assert vr.static_routes[1].source_order == inventory_order["v6-route"]
    assert lr.vrfs[0].static_routes[0].source_order == inventory_order["lr-v6"]
    assert [route.name for route in build_derived_views(config).static_routes] == ["v4-route", "v6-route", "lr-v6"]
