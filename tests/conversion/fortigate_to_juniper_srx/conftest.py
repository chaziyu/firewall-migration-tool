from pathlib import Path

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx import (
    SRXInterfaceMapping,
    SRXMigrationOptions,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


FIXTURES = Path(__file__).parents[2] / "fixtures" / "fortigate"


@pytest.fixture
def explicit_analysis():
    return FortiGateSourceReporter().analyze_source(
        (FIXTURES / "multi_vendor_explicit.conf").read_text(encoding="utf-8")
    )


@pytest.fixture
def policy_analysis():
    source = (FIXTURES / "multi_vendor_explicit.conf").read_text(encoding="utf-8")
    source = source.replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    return FortiGateSourceReporter().analyze_source(source)


@pytest.fixture
def blocker_analysis():
    return FortiGateSourceReporter().analyze_source(
        (FIXTURES / "multi_vendor_blockers.conf").read_text(encoding="utf-8")
    )


@pytest.fixture
def complete_options():
    return SRXMigrationOptions(
        source_vdom="root",
        target_context="root",
        target_version="25.2R1",
        target_mode="standalone",
        routing_table="inet.0",
        timezone="Asia/Kuala_Lumpur",
        interfaces={"root": {
            "lan": SRXInterfaceMapping("ge-0/0/0", 0),
            "wan": SRXInterfaceMapping("ge-0/0/1", 0),
            "app-vlan": SRXInterfaceMapping("ge-0/0/0", 120),
        }},
        zones={"root": {"inside": "inside-zone", "outside": "outside-zone"}},
    )
