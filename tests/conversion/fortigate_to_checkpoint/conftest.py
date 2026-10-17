import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.options import CPMigrationOptions
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config vdom
    edit root
        config firewall address
            edit "clients"
                set type ipmask
                set subnet 10.10.0.0 255.255.255.0
            next
            edit "web"
                set type ipmask
                set subnet 203.0.113.10 255.255.255.255
            next
            edit "any"
                set type ipmask
                set subnet 192.0.2.77 255.255.255.255
            next
        end
        config firewall addrgrp
            edit "client-group"
                set member "clients"
            next
        end
        config firewall service custom
            edit "https"
                set tcp-portrange 443
            next
            edit "dns"
                set udp-portrange 53
            next
        end
        config firewall service group
            edit "web-services"
                set member "https" "dns"
            next
        end
        config firewall policy
            edit 10
                set name "allow-web"
                set srcintf "any"
                set dstintf "any"
                set srcaddr "client-group"
                set dstaddr "web"
                set service "https"
                set srcaddr-negate disable
                set dstaddr-negate disable
                set service-negate disable
                set schedule "always"
                set action accept
                set status enable
                set nat disable
                set utm-status disable
                set logtraffic all
            next
            edit 20
                set name "deny-rest"
                set srcintf "any"
                set dstintf "any"
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
                set srcaddr-negate disable
                set dstaddr-negate disable
                set service-negate disable
                set schedule "always"
                set action deny
                set status enable
                set nat disable
                set utm-status disable
                set logtraffic disable
            next
        end
        config router static
            edit 1
                set dst 10.20.0.0 255.255.255.0
                set gateway 10.10.0.254
                set status enable
                set blackhole disable
            next
        end
    next
end
'''


@pytest.fixture
def checkpoint_source_text():
    return SOURCE


@pytest.fixture
def checkpoint_analysis(checkpoint_source_text):
    return FortiGateSourceReporter().analyze_source(checkpoint_source_text)


@pytest.fixture
def checkpoint_options():
    return CPMigrationOptions(
        source_vdom="root",
        management_target="cp-mgmt-test",
        management_domain="Default Domain",
        management_api_version="1.8.1",
        gaia_target="cp-gw-test",
        policy_package="Migration Package",
        access_layer="Network",
        install_on=("cp-gw-test",),
        insertion_anchor="Cleanup Drop",
        insertion_relation="above",
        target_cleanup_action="Drop",
    )
