from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_activation_and_deactivation_accounting():
    fixture_path = JUNIPER_FIXTURES_DIR / "activation.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    assert_no_silent_loss(res, total_input_commands=19, expected_unsupported=0)
