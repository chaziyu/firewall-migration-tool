import pytest
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.parser import FortiGateParser

def test_parse_system_global():
    config = """
config system global
    set hostname "GENE-FW2"
    set admin-sport 8443
    set timezone 60
end
    """
    tokenizer = FortiGateTokenizer(config)
    parser = FortiGateParser(tokenizer)
    cfg = parser.parse()
    
    assert cfg.system_global is not None
    assert cfg.system_global.hostname == "GENE-FW2"
    assert cfg.system_global.admin_sport == 8443

def test_parse_interface():
    config = """
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
        set role lan
    next
    edit "port2"
        set vdom "root"
        set ip 10.0.0.2 255.255.255.0
        set allowaccess ping
        set type physical
        set role wan
    next
end
    """
    tokenizer = FortiGateTokenizer(config)
    parser = FortiGateParser(tokenizer)
    cfg = parser.parse()
    
    assert len(cfg.interfaces) == 2
    
    intf1 = cfg.interfaces[0]
    assert intf1.name == "port1"
    assert intf1.ip == "10.0.0.1 255.255.255.0"
    assert "ssh" in intf1.allowaccess
    assert intf1.role == "lan"

def test_parse_firewall_address():
    config = """
config firewall address
    edit "local_net"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "google"
        set type fqdn
        set fqdn "google.com"
    next
end
    """
    tokenizer = FortiGateTokenizer(config)
    parser = FortiGateParser(tokenizer)
    cfg = parser.parse()
    
    assert len(cfg.addresses) == 2
    assert cfg.addresses[0].name == "local_net"
    assert cfg.addresses[0].subnet == "192.168.1.0 255.255.255.0"
    
    assert cfg.addresses[1].name == "google"
    assert cfg.addresses[1].type == "fqdn"
    assert cfg.addresses[1].fqdn == "google.com"

def test_parse_firewall_policy():
    config = """
config firewall policy
    edit 1
        set name "allow_out"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
    """
    tokenizer = FortiGateTokenizer(config)
    parser = FortiGateParser(tokenizer)
    cfg = parser.parse()
    
    assert len(cfg.policies) == 1
    p = cfg.policies[0]
    assert p.id == 1
    assert p.name == "allow_out"
    assert p.srcintf == ["lan"]
    assert p.action == "accept"
    assert p.nat == "enable"

def test_parse_nested_config():
    config = """
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "virtual-wan-link"
        next
    end
end
    """
    tokenizer = FortiGateTokenizer(config)
    parser = FortiGateParser(tokenizer)
    cfg = parser.parse()
    
    # We silently ignored the nested ones for now in mvp parser
    # But it shouldn't crash.
    assert cfg.sdwan is not None
    assert cfg.sdwan.status == "enable"

