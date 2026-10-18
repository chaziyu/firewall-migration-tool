import json

import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.application.workflow import build_review
from fwmigrate.conversion.fortigate_to_checkpoint.rendering.management import CPManagementRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


@pytest.mark.parametrize("start,end,valid", [("192.0.2.10", "192.0.2.20", True),
    ("192.0.2.20", "192.0.2.10", False), ("2001:db8::1", "2001:db8::2", False)])
def test_explicit_ipv4_range_uses_verified_api_1_8_1_fields(checkpoint_source_text, checkpoint_options, start, end, valid):
    text = checkpoint_source_text.replace('set type ipmask\n                set subnet 10.10.0.0 255.255.255.0',
        f'set type iprange\n                set start-ip {start}\n                set end-ip {end}', 1)
    analysis = FortiGateSourceReporter().analyze_source(text)
    review = build_review(analysis, checkpoint_options, "source")
    item = next(row for row in review["plan"].items if row.family == "address" and row.source_name == "clients")
    assert bool(item.blockers) is not valid
    operations = json.loads(CPManagementRenderer().render(review["plan"]).management_text)["operations"]
    ranges = [row for row in operations if row["path"] == "/web_api/add-address-range"]
    assert bool(ranges) is valid
    if valid:
        body = ranges[0]["request_body_template"]
        assert body["ipv4-address-first"] == start
        assert body["ipv4-address-last"] == end
        assert body["nat-settings"] == {"auto-rule": False}
