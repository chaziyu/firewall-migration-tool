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
