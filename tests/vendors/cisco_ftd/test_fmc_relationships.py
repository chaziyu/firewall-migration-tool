from pathlib import Path
from copy import deepcopy

from fwmigrate.vendors.cisco_ftd.source_report import extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_identity_and_vpn_relationships_are_derived_without_source_mutation():
    result = extract_cisco_ftd_source(FIXTURE.read_text(encoding="utf-8"))
    before = deepcopy(result.config)
    derived = build_ftd_derived_views(result.config)
    assert derived.identity_relationships[0]["user"] == "operator"
    assert derived.vpn_relationships[0]["endpoints"] == ["HQ"]
    assert result.config == before
