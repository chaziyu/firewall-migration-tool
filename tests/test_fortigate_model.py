import pytest
from pydantic import ValidationError
from fwmigrate.parsers.fortigate.model import (
    FGAddress, FGPolicy, FGConfig, FGInterface, FGService
)

def test_fgaddress_model():
    # Test valid subnet address
    addr1 = FGAddress(name="internal_net", type="ipmask", subnet="192.168.1.0 255.255.255.0")
    assert addr1.name == "internal_net"
    assert addr1.subnet == "192.168.1.0 255.255.255.0"
    
    # Test FQDN address
    addr2 = FGAddress(name="google", type="fqdn", fqdn="google.com")
    assert addr2.type == "fqdn"
    assert addr2.fqdn == "google.com"

def test_fgpolicy_model():
    policy = FGPolicy(
        id=1,
        name="allow_internet",
        srcintf=["lan"],
        dstintf=["wan1", "wan2"],
        srcaddr=["all"],
        dstaddr=["all"],
        action="accept",
        service=["HTTP", "HTTPS"],
        nat="enable"
    )
    assert policy.id == 1
    assert len(policy.dstintf) == 2
    assert policy.nat == "enable"

def test_fginterface_model():
    intf = FGInterface(
        name="port1",
        ip="10.0.0.1 255.255.255.0",
        allowaccess=["ping", "https", "ssh"],
        role="lan"
    )
    assert intf.name == "port1"
    assert "ping" in intf.allowaccess
    assert intf.role == "lan"

def test_fginterface_does_not_invent_type():
    intf = FGInterface(name="vlan20")

    assert intf.type is None

def test_fgservice_model():
    svc = FGService(
        name="custom_tcp",
        protocol="tcp/udp/sctp",
        tcp_portrange="8080-8081"
    )
    assert svc.name == "custom_tcp"
    assert svc.tcp_portrange == "8080-8081"

def test_fgconfig_root():
    config = FGConfig()
    assert len(config.policies) == 0
    assert len(config.interfaces) == 0
    
    config.interfaces.append(FGInterface(name="port1"))
    config.policies.append(FGPolicy(
        id=1, srcintf=["port1"], dstintf=["wan"], 
        srcaddr=["all"], dstaddr=["all"], service=["ALL"]
    ))
    
    assert len(config.interfaces) == 1
    assert len(config.policies) == 1

def test_validation_error():
    with pytest.raises(ValidationError):
        # Missing required field 'id'
        FGPolicy(
            srcintf=["lan"],
            dstintf=["wan"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["ALL"]
        )
