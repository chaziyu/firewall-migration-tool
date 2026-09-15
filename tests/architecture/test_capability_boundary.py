from inspect import signature

from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.ir import IRConfig


def test_capability_boundary_is_canonical_and_job_independent():
    parameter = signature(CapabilityAnalyzer.analyze).parameters["ir_config"]
    assert parameter.annotation in (IRConfig, "IRConfig")
    assert "jobs" not in CapabilityAnalyzer.analyze.__code__.co_filename
