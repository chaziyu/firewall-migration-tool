from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.vendors.fortigate.extraction.coverage import (
    build_typed_source_identity_index,
    build_typed_source_inventory,
    find_typed_source_object,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


_SAMPLE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n"
    "-----END CERTIFICATE-----"
)


def test_certificates_local_in_logging_and_saml_are_typed_and_redact_private_keys():
    source = f"""config vpn certificate local
    edit "gw-cert"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
SUPER-SECRET-PRIVATE-KEY-BODY
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "{_SAMPLE_PEM}"
        set password "CERT-SECRET-PASS"
    next
end
config vpn certificate ca
    edit "corp-ca"
        set certificate "{_SAMPLE_PEM}"
    next
end
config vpn certificate remote
    edit "peer-cert"
        set certificate "{_SAMPLE_PEM}"
    next
end
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS" "SSH"
        set schedule "always"
    next
end
config firewall local-in-policy6
    edit 2
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "ALL"
        set schedule "always"
    next
end
config log fortianalyzer setting
    set status enable
    set server "10.0.0.50"
end
config log fortiguard setting
    set status disable
end
config system storage
    edit "HD1"
        set status enable
        set media-status enable
        set size 102400
    next
end
config user saml
    edit "okta-saml"
        set cert "gw-cert"
        set entity-id "https://fw.example.test/saml/metadata"
        set idp-cert "peer-cert"
    next
end
config file-filter profile
    edit "ff-1"
    next
end
config emailfilter profile
    edit "ef-1"
    next
end
config waf profile
    edit "waf-1"
    next
end
config firewall policy
    edit 10
        set srcintf "wan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
        set file-filter-profile "ff-1"
        set emailfilter-profile "ef-1"
        set waf-profile "waf-1"
    next
end
"""
    sanitized = sanitize_source("fortigate", source)
    assert "SUPER-SECRET-PRIVATE-KEY-BODY" not in sanitized
    assert "CERT-SECRET-PASS" not in sanitized

    analysis = FortiGateSourceReporter().analyze_source(sanitized)
    config = analysis.extracted.config
    dumped = config.model_dump_json()
    assert "SUPER-SECRET-PRIVATE-KEY-BODY" not in dumped
    assert "CERT-SECRET-PASS" not in dumped

    assert [(c.name, c.store, c.private_key_configured, c.password_configured) for c in config.certificates] == [
        ("gw-cert", "local", True, True),
        ("corp-ca", "ca", False, False),
        ("peer-cert", "remote", False, False),
    ]
    assert "BEGIN CERTIFICATE" in (config.certificates[0].certificate or "")

    assert len(config.local_in_policies) == 2
    assert config.local_in_policies[0].address_family == "ipv4"
    assert config.local_in_policies[0].intf == ["wan1"]
    assert config.local_in_policies[0].service == ["HTTPS", "SSH"]
    assert config.local_in_policies[1].address_family == "ipv6"
    assert config.local_in_policies[1].action == "deny"

    assert config.fortianalyzer_settings[0].status == "enable"
    assert config.fortianalyzer_settings[0].server == "10.0.0.50"
    assert config.log_fortiguard_settings[0].status == "disable"
    assert config.system_storages[0].size == 102400
    assert config.saml_servers[0].entity_id == "https://fw.example.test/saml/metadata"

    pol = config.policies[0]
    assert pol.file_filter_profile == "ff-1"
    assert pol.emailfilter_profile == "ef-1"
    assert pol.waf_profile == "waf-1"

    inventory = build_typed_source_inventory(config)
    identity_index = build_typed_source_identity_index(inventory)
    for record in analysis.extracted.source_objects:
        assert find_typed_source_object(identity_index, record) is not None, record.source_path
