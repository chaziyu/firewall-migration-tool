"""Phase 27 collector/parser contract checks."""

from __future__ import annotations

from fwmigrate.parsers.checkpoint.loader import group_response_pages
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def test_package_uid_prevents_same_named_rulebases_from_merging():
    responses = [
        CheckPointResponse(command="show-nat-rulebase", domain_uid="D", package="Shared", package_uid="P1", data={"rulebase": []}),
        CheckPointResponse(command="show-nat-rulebase", domain_uid="D", package="Shared", package_uid="P2", data={"rulebase": []}),
    ]
    grouped = group_response_pages(responses)
    assert len(grouped) == 2


def test_layer_uid_prevents_same_named_layers_from_merging():
    responses = [
        CheckPointResponse(command="show-access-rulebase", domain_uid="D", package_uid="P", layer="Inline", layer_uid="L1", data={"rulebase": []}),
        CheckPointResponse(command="show-access-rulebase", domain_uid="D", package_uid="P", layer="Inline", layer_uid="L2", data={"rulebase": []}),
    ]
    assert len(group_response_pages(responses)) == 2
