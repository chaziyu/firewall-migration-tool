import pytest
from datetime import datetime
from fg2pan.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, AddressType,
    IRAddressGroup, IRService, IRServicePort, ServiceProtocol, IRServiceGroup,
    IRPolicy, PolicyAction, IRNATRule, NATType, IRVPNTunnel, IRRoute,
    IRAuditEntry, MigrationConfidence
)
from fg2pan.report.migration_report import MigrationReporter

def test_migration_reporter_minimal():
    ir = IRConfig(metadata=IRMetadata(hostname="Test-FW"))
    reporter = MigrationReporter(ir)
    report = reporter.generate_report()
    
    assert "# 🛡️ Firewall Migration & Configuration Report" in report
    assert "**Hostname:** `Test-FW`" in report
    assert "## 1. Executive Summary & Migration Health" in report
    assert "## 2. ⚠️ Audit Trail & Action Items" in report
    assert "No migration warnings or manual action items flagged" in report
    assert "## 3. 🌐 Network Architecture & Zones" in report
    assert "## 4. 📦 Object Inventory" in report
    assert "## 5. 📋 Rulebase & Policies" in report

def test_migration_reporter_full_inventory():
    ir = IRConfig(
        metadata=IRMetadata(hostname="HQ-FW1"),
        zones=[IRZone(name="trust", interfaces=["port1"])],
        interfaces=[
            IRInterface(name="port1", zone="trust", ip="10.0.1.1/24", description="LAN Gateway")
        ],
        addresses=[
            IRAddress(name="srv_app", type=AddressType.HOST, value="10.0.1.50/32", description="App Server")
        ],
        address_groups=[
            IRAddressGroup(name="app_servers", members=["srv_app"], description="All App Servers")
        ],
        services=[
            IRService(name="custom_http", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8080")])
        ],
        service_groups=[
            IRServiceGroup(name="web_services", members=["custom_http"])
        ],
        policies=[
            IRPolicy(
                name="Allow_App",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["app_servers"],
                destination=["any"],
                service=["custom_http"],
                action=PolicyAction.ALLOW,
                disabled=False,
                description="Allow app egress"
            )
        ],
        nat_rules=[
            IRNATRule(
                name="SNAT_Internet",
                type=NATType.SOURCE,
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["10.0.1.0/24"],
                destination=["any"],
                translated_source="203.0.113.5",
                description="Outbound PAT"
            )
        ],
        vpn_tunnels=[
            IRVPNTunnel(
                name="Branch_VPN",
                peer_address="198.51.100.1",
                local_interface="port2",
                ike_version="v2",
                psk="secret123"
            )
        ],
        routes=[
            IRRoute(
                name="Default_Route",
                destination="0.0.0.0/0",
                next_hop="203.0.113.1",
                interface="port2",
                metric=10
            )
        ],
        audit_entries=[
            IRAuditEntry(
                id="Rule_1",
                category="Policy",
                message="UTM Profile Group requires review.",
                confidence=MigrationConfidence.PARTIAL
            )
        ]
    )
    
    reporter = MigrationReporter(ir)
    report = reporter.generate_report()
    
    # Assert Header & Stats
    assert "**Hostname:** `HQ-FW1`" in report
    assert "Total Processed Objects" in report
    assert "Partial Confidence" in report
    
    # Assert Audit Trail
    assert "UTM Profile Group requires review" in report
    assert "`Rule_1`" in report
    
    # Assert Network & Zone Table
    assert "| `port1` | `trust` | `10.0.1.1/24` | LAN Gateway |" in report
    assert "| `Default_Route` | `0.0.0.0/0` | `203.0.113.1` | `port2` | 10 |" in report
    assert "| `Branch_VPN` | `198.51.100.1` | `port2` | V2 | ✅ Configured |" in report
    
    # Assert Objects
    assert "| `srv_app` | `host` | `10.0.1.50/32` | App Server |" in report
    assert "| `app_servers` | `srv_app` | All App Servers |" in report
    assert "| `custom_http` | `TCP` | `8080` | - |" in report
    
    # Assert Policies
    assert "| 1 | `Allow_App` | `trust` | `untrust` | `app_servers` | `any` | `custom_http` | 🟢 `ALLOW` | Active |" in report
    assert "| `SNAT_Internet` | `SOURCE` | `trust` | `untrust` | `10.0.1.0/24` | `any` | `203.0.113.5` |" in report
