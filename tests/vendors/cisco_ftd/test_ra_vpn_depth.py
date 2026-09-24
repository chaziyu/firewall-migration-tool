"""One end-to-end FMC RA VPN source/report contract."""

from copy import deepcopy
from io import BytesIO
import json

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.export.excel import export_ftd_excel
from fwmigrate.vendors.cisco_ftd.source_report import extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config
from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview


def test_ra_vpn_source_relationships_and_reports():
    ref = lambda id, name: {"id": id, "name": name}
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d"}, "objects": {
        "networks": [{"id": "net", "name": "inside"}],
        "ipv4addresspools": [{"id": "v4", "name": "pool4", "startAddress": "192.0.2.1",
                              "endAddress": "192.0.2.20"}],
        "ipv6addresspools": [{"id": "v6", "name": "pool6", "value": "2001:db8::/64"}],
        "realms": [{"id": "realm", "name": "Directory"}],
        "grouppolicies": [{"id": "gp", "name": "Employees", "vpnAccess": False,
                           "dnsServers": ["192.0.2.53"], "winsServers": [], "domainName": "example.test",
                           "splitTunnelPolicy": "INCLUDE", "splitTunnelNetworks": [ref("net", "inside")],
                           "splitDns": ["internal.example.test"], "simultaneousLogins": 2,
                           "sessionSettings": {"idleTimeout": 30}},
                          {"id": "nested-gp", "name": "Nested FMC", "protocol": "SSL",
                           "generalSettings": {"primaryDNSServer": ref("dns", "Primary DNS"),
                               "addressAssignment": {"defaultDomainName": "corp.example",
                                   "ipv4LocalAddressPool": [ref("v4", "pool4")]},
                               "splitTunnelSettings": {"ipv4SplitTunnelPolicy": "TUNNEL_ALL",
                                   "splitDNSDomainList": "internal.example",
                                   "splitTunnelACL": ref("acl", "Split ACL")}},
                           "anyConnectSettings": {"connectionSettings": {"enableClientDPD": True},
                               "vpnClientProfile": ref("client-profile", "Client")},
                           "advancedSettings": {"sessionSettings": {"simultaneousLoginPerUser": 3}}}],
        "certificatemaps": [{"id": "map", "name": "Certificate map", "conditions": {"issuer": "CA"},
                             "connectionProfile": ref("cp", "Employees VPN")}],
        "ravpns": [{"id": "ra", "name": "Remote access", "targetDevices": [ref("device", "FTD")],
                    "connectionProfiles": [ref("cp", "Employees VPN")],
                    "certificateMapSettings": [{"enableCertificateToConnectionProfileMapping": True,
                        "useGroupURL": False, "certificateToConnectionProfileMap": [
                            {"certificateMap": ref("map", "Certificate map"),
                             "connectionProfile": ref("cp", "Employees VPN")}]}],
                    "sslTlsSettings": {"minimumVersion": "TLS1.2"},
                    "connection_profiles": [{"id": "cp", "name": "Employees VPN",
                        "groupAlias": [{"aliasName": "employees", "enabled": True}],
                        "groupUrl": [{"aliasUrl": ref("url", "vpn.example.test"), "enabled": True}],
                        "authenticationMethod": "AAA_ONLY", "primaryAuthenticationServer":
                            {**ref("realm", "Directory"), "type": "IdentityRealm"},
                        "authorizationServer": ref("authz", "Authorization"),
                        "accountingServer": ref("acct", "Accounting"),
                        "groupPolicy": ref("gp", "Employees"),
                        "ipv4AddressPool": [ref("v4", "pool4")], "ipv6AddressPool": [ref("v6", "pool6")],
                        "certificates": None,
                        "certificateMaps": [ref("map", "Certificate map")],
                        "password": "do-not-export"}],
                    "address_assignment_settings": [{"id": "assign", "name": "Assignment",
                        "ipAddressReuseInterval": 10, "useDHCP": False}],
                    "ipsec_advanced_settings": [{"id": "ipsec", "name": "IPsec advanced",
                        "ikev2settings": {"maximumNumberOfSAsAllowed": 1},
                        "ipsecsettings": {"enableFragmentationBeforeEncryption": False},
                        "natKeepaliveMessageTraversal": {"enabled": True}}],
                    "secure_client_customization_settings": [{"id": "client", "name": "Client",
                        "clientPackages": [ref("pkg", "Secure Client")], "token": "secret-token"}]}],
    }}
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config
    profile = config.ra_vpn_connection_profiles[0]
    group = config.group_policies[0]
    assert [ref.source_id for ref in profile.address_pools] == ["v4", "v6"]
    assert profile.alias[0]["aliasName"] == "employees" and profile.group_url[0]["enabled"]
    assert (profile.authentication_server.source_id, profile.authorization.source_id,
            profile.accounting_server.source_id) == ("realm", "authz", "acct")
    assert profile.default_group_policy.source_id == "gp"
    assert profile.certificates is None and "certificates" in profile.explicit_fields
    assert group.vpn_access is False and "vpn_access" in group.explicit_fields
    assert group.split_tunnel_policy == "INCLUDE" and group.split_tunnel_networks[0].source_id == "net"
    assert group.split_dns == ["internal.example.test"] and group.wins_servers == []
    nested = config.group_policies[1]
    assert nested.protocols == "SSL" and nested.dns_servers[0]["id"] == "dns"
    assert nested.domain_name == "corp.example" and nested.address_pools[0].source_id == "v4"
    assert nested.split_tunnel_policy == {"ipv4SplitTunnelPolicy": "TUNNEL_ALL"}
    assert nested.split_tunnel_acl.source_id == "acl" and nested.split_tunnel_networks is None
    assert nested.split_dns["splitDNSDomainList"] == "internal.example"
    assert nested.simultaneous_logins == 3 and nested.secure_client[0].source_id == "client-profile"
    assert "address_pools" not in group.explicit_fields and group.address_pools is None
    assert config.ra_vpn_address_assignment_settings[0].reuse_delay == 10
    assert config.ra_vpn_address_assignment_settings[0].use_dhcp is False
    assert config.ra_vpn_ipsec_settings[0].ikev2_settings["maximumNumberOfSAsAllowed"] == 1
    before = deepcopy(config)
    derived = build_ftd_derived_views(config)
    assert config == before
    assert any(row["field"] == "split_tunnel_networks" and row["target_id"] == "net"
               for row in derived.resolved_references)
    assert any(row["field"] == "default_group_policy" and row["target_id"] == "gp"
               for row in derived.resolved_references)
    assert any(row["field"] == "authentication_server" and row["target_id"] == "realm"
               for row in derived.resolved_references)
    assert any(row["kind"] == "certificate-map-selection" and row["enabled"] is True
               for row in derived.ra_vpn_relationships)
    assert not any(issue.field in {"authorization", "accounting_server"}
                   for issue in derived.unresolved_references)
    preview = build_ftd_preview(result)
    assert preview["ra_vpn"]["ra_vpn_connection_profiles"][0]["authentication_method"] == "AAA_ONLY"
    output = BytesIO()
    export_ftd_excel(result, output)
    workbook = load_workbook(output, read_only=True)
    assert workbook["RA Connection Profiles"]["D2"].value and workbook["RA Group Policies"]["L2"].value == "INCLUDE"
    rendered = json.dumps(config.model_dump()) + json.dumps(preview, default=str) + str(workbook["RA Connection Profiles"]["R2"].value)
    assert "do-not-export" not in rendered and "secret-token" not in rendered
    missing = deepcopy(config)
    missing.ra_vpn_connection_profiles[0].default_group_policy.source_id = "missing"
    missing_derived = build_ftd_derived_views(missing)
    assert any(issue.field == "default_group_policy" for issue in missing_derived.unresolved_references)
    assert any(issue.category == "unresolved-reference" for issue in
               validate_ftd_config(missing, missing_derived).issues)


def test_ra_access_interface_uses_target_device_scope():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d"},
        "devices": [{"id": id, "name": id, "resources": {"ftd_interfaces": [
            {"id": f"if-{id}", "name": "outside"}]}} for id in ("a", "b")],
        "objects": {"ravpns": [{"id": "ra", "name": "Remote", "targetDevices": [{"id": "a", "name": "a"}],
                               "accessInterfaces": [{"name": "outside"}]}]}}
    single = extract_cisco_ftd_source(json.dumps(payload)).derived
    assert any(row["field"] == "access_interfaces" and row["target_id"] == "if-a"
               for row in single.resolved_references)
    payload["objects"]["ravpns"][0]["targetDevices"].append({"id": "b", "name": "b"})
    multiple = extract_cisco_ftd_source(json.dumps(payload)).derived
    assert any(issue.field == "access_interfaces" and issue.status == "AMBIGUOUS"
               for issue in multiple.unresolved_references)
