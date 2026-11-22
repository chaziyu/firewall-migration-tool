from fwmigrate.vendors.fortigate.model.interface import FGInterface, FGInterfaceSecondaryIP
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.validation.validator import validate_config


def test_public_facing_management_access_warns_for_wan_and_public_ips():
    config = FGConfig(
        interfaces=[
            FGInterface(name="wan1", role="wan", ip="198.51.100.2 255.255.255.0", allowaccess=["https", "ssh", "ping"]),
            FGInterface(name="port2", role="lan", ip="1.1.1.2 255.255.255.0", allowaccess=["http"]),
            FGInterface(name="port3", role="lan", ip="192.168.10.1 255.255.255.0", allowaccess=["https", "ssh"]),
            FGInterface(name="cgnat1", ip="100.64.1.2 255.255.255.0", allowaccess=["https"]),
            FGInterface(
                name="sec_pub",
                ip="10.0.0.1 255.255.255.0",
                secondary_ips=[FGInterfaceSecondaryIP(id=1, ip="9.9.9.9 255.255.255.0", allowaccess=["telnet"])],
            ),
        ]
    )
    result = validate_config(config)
    exposed = [issue for issue in result.issues if issue.domain == "interface" and issue.field == "allowaccess"]
    assert [issue.object_name for issue in exposed] == ["wan1", "port2", "sec_pub"]
    assert "https, ssh" in exposed[0].message
    assert "http" in exposed[1].message
    assert "telnet" in exposed[2].message
