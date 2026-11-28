"""Tests for Phase 2 FortiGate extraction, coverage, and preview parity."""

from __future__ import annotations

from fwmigrate.vendors.fortigate.extraction.coverage import (
    build_typed_source_identity_index,
    build_typed_source_inventory,
    extraction_status,
    find_typed_source_object,
    supports_path,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


_FG_PARITY_CONF = """#config-version=FGT60F-7.4.4-FW-build2662-240501:opmode=0:vdom=0:user=admin
config system interface
    edit "mgmt"
        set vdom "root"
        set dedicated-to management
        set ip 192.168.100.1 255.255.255.0
        set mtu-override enable
        set dhcp-relay-service enable
        set allowaccess https ssh ping
        config ipv6
            set ip6-mode static
            set ip6-address 2001:db8:1::1/64
            set ip6-allowaccess ping https
        end
    next
end
config system password-policy
    set status enable
    set apply-to admin-password ipsec-preshared-key
    set minimum-length 12
    set min-upper-case-letter 1
    set min-lower-case-letter 1
    set min-number 1
    set min-non-alphanumeric 1
    set expire-status enable
    set expire-day 90
    set reuse-password disable
end
config log setting
    set fwpolicy-implicit-log enable
    set brief-traffic-format enable
    set local-out-ioc-detection enable
end
config log threat-weight
    set status enable
    set blocked-connection medium
    config level
        set low 5
        set medium 10
        set high 30
        set critical 50
    end
    config ips
        set info-severity off
        set critical-severity critical
    end
    config malware
        set botnet-connection high
        set virus-infected critical
    end
    config web
        edit 1
            set category 26
            set level high
        next
    end
    config application
        edit 1
            set category 15
            set level medium
        next
    end
end
config log fortianalyzer2 setting
    set status enable
    set server "10.20.30.40"
end
config firewall local-in-policy
    edit 1
        set intf "mgmt"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set schedule "always"
        set status enable
    next
end
config vpn certificate local
    edit "mgmt-cert"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
SECRET-KEY-SHOULD-NOT-LEAK
-----END ENCRYPTED PRIVATE KEY-----"
        set comments "Management cert"
    next
end
"""


def test_fortigate_phase2_parity_extraction_coverage_and_preview():
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(_FG_PARITY_CONF)
    extracted = analysis.extracted
    cfg = extracted.config

    # Interface parity: dedicated-to, mtu-override, dhcp-relay-service, nested ipv6
    assert len(cfg.interfaces) == 1
    mgmt = cfg.interfaces[0]
    assert mgmt.dedicated_to == "management"
    assert mgmt.mtu_override == "enable"
    assert mgmt.dhcp_relay_service == "enable"
    assert mgmt.ipv6 is not None
    assert mgmt.ipv6.ip6_mode == "static"
    assert mgmt.ipv6.ip6_address == "2001:db8:1::1/64"
    assert mgmt.ipv6.ip6_allowaccess == ["ping", "https"]

    # System password-policy
    assert len(cfg.system_password_policies) == 1
    pp = cfg.system_password_policies[0]
    assert pp.status == "enable"
    assert pp.apply_to == ["admin-password", "ipsec-preshared-key"]
    assert pp.minimum_length == 12
    assert pp.expire_day == 90
    assert pp.reuse_password == "disable"

    # Log setting brief-traffic-format scalar (not int)
    assert len(cfg.log_settings) == 1
    assert cfg.log_settings[0].brief_traffic_format == "enable"
    assert cfg.log_settings[0].local_out_ioc_detection == "enable"

    # Log threat-weight nested blocks
    assert len(cfg.log_threat_weights) == 1
    tw = cfg.log_threat_weights[0]
    assert tw.status == "enable"
    assert tw.level is not None and tw.level.critical == 50
    assert tw.ips is not None and tw.ips.critical_severity == "critical"
    assert tw.malware is not None and tw.malware.botnet_connection == "high"
    assert len(tw.web) == 1 and tw.web[0].category == 26 and tw.web[0].level == "high"
    assert len(tw.application) == 1 and tw.application[0].category == 15

    # Multi-FortiAnalyzer setting
    assert len(cfg.fortianalyzer_settings) == 1
    assert cfg.fortianalyzer_settings[0].target_name == "fortianalyzer2"
    assert cfg.fortianalyzer_settings[0].server == "10.20.30.40"

    # Zero MODEL_GAP / SOURCE_ONLY across all new sections
    typed = build_typed_source_inventory(cfg)
    index = build_typed_source_identity_index(typed)
    statuses = [
        extraction_status(supports_path(rec.source_path), find_typed_source_object(index, rec), rec)
        for rec in extracted.source_objects
    ]
    assert "MODEL_GAP" not in statuses
    assert "SOURCE_ONLY" not in statuses

    # Preview includes new sections and redacts certificate secrets
    report = reporter.build_preview(analysis)
    sections = report["sections"]
    assert sections["interfaces"][0]["dedicated_to"] == "management"
    assert sections["interfaces"][0]["ipv6_address"] == "2001:db8:1::1/64"
    assert len(sections["system_password_policies"]) == 1
    assert len(sections["fortianalyzer_settings"]) == 1
    assert len(sections["local_in_policies"]) == 1
    assert len(sections["certificates"]) == 1
    assert sections["certificates"][0]["private_key_configured"] is True
    assert "SECRET-KEY-SHOULD-NOT-LEAK" not in str(report)
