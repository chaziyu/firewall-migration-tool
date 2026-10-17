import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.options import ASAMigrationOptions
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config system interface
    edit "inside"
        set type physical
        set ip 10.0.0.1 255.255.255.0
        set status up
    next
    edit "outside"
        set type physical
        set ip 198.51.100.1 255.255.255.0
        set status up
    next
end
config firewall address
    edit "clients"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "web"
        set type ipmask
        set subnet 203.0.113.10 255.255.255.255
    next
end
config firewall service custom
    edit "https"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 10
        set name "allow-https"
        set srcintf "inside"
        set dstintf "any"
        set srcaddr "clients"
        set dstaddr "web"
        set service "https"
        set schedule "always"
        set action accept
        set logtraffic disable
        set status enable
    next
end
'''


@pytest.fixture
def asa_source():
    return FortiGateSourceReporter().analyze_source(SOURCE)


@pytest.fixture
def asa_source_text():
    return SOURCE


@pytest.fixture
def asa_options():
    return ASAMigrationOptions(
        source_vdom="root", target_context="single", target_version="9.20", target_mode="routed",
        interfaces={"root": {
            "inside": {"interface": "GigabitEthernet0/1", "nameif": "inside", "security_level": 100},
            "outside": {"interface": "GigabitEthernet0/0", "nameif": "outside", "security_level": 0},
        }},
    )
