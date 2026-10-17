from pathlib import Path

import pytest

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.source_reporting import source_reporters
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


SOURCE = (Path(__file__).parents[2] / 'fixtures' / 'palo_alto' / 'fortigate_conversion.xml').read_text(encoding='utf-8')


@pytest.fixture
def analyze():
    register_builtin_source_reporters()
    return source_reporters.get("palo_alto").analyze_source


@pytest.fixture
def analysis(analyze):
    return analyze(SOURCE)


@pytest.fixture
def options(analysis):
    from fwmigrate.conversion.palo_alto_to_fortigate.planning.source_scope import identity

    scope = next(s for s in analysis.config.scopes if s.kind == "vsys")
    return {"source_scope": pan_scope_identity(scope), "vdom": "root",
            "interfaces": {"ethernet1/1": "port1", "ethernet1/2": "port2"}, "zones": {"trust": "inside", "untrust": "outside"},
            "profile": {"fortios_version": "7.4.6", "operating_mode": "nat", "ngfw_mode": "profile-based", "nat_mode": "central", "vdom_mode": "single", "ports": ["port1", "port2"]},
            "policy_settings": {identity(analysis.config.security_rules[0], "policy"): {"schedule": "always"}}}
