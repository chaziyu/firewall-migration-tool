from __future__ import annotations

from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_automatic_nat_stays_on_the_owner_object():
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-hosts",
        "data": {"objects": [{"type": "host", "name": "Web", "nat-settings": {"auto-rule": True}}]},
    }]}))

    host = result.config.hosts[0]
    assert type(host) is CPHost
    assert host.nat_settings == {"auto-rule": True}
    assert not result.config.nat_rules


def test_paginated_pages_produce_one_operation_diagnostic():
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [
        {"command": "show-hosts", "from": 1, "to": 1, "total": 2, "data": {"objects": [{"type": "host", "name": "a"}]}},
        {"command": "show-hosts", "from": 2, "to": 2, "total": 2, "data": {"objects": [{"type": "host", "name": "b"}]}},
    ]}))

    assert len(result.collection) == 1
    assert result.collection[0].complete is True
    assert [host.name for host in result.config.hosts] == ["a", "b"]


def test_scope_selection_is_preserved_in_source_report():
    source = '{"responses": [{"command": "show-hosts", "domain": "A", "data": {"objects": []}}, {"command": "show-hosts", "domain": "B", "data": {"objects": []}}]}'

    result = extract_checkpoint_source(source)

    assert result.scope.ambiguous is True
    assert "multiple-domains-without-selector" in result.scope.reasons
