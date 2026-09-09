import pytest
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.core.optimizer import RuleOptimizer
from tests.fixture_paths import VENDOR_FIXTURES

GOLDEN_CASES = list(VENDOR_FIXTURES.items())

@pytest.mark.parametrize("vendor_id, file_path", GOLDEN_CASES)
def test_golden_parsing_and_generation(vendor_id, file_path):
    assert file_path.exists(), f"Golden file {file_path} not found"

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Parse via PluginRegistry
    parser = PluginRegistry.get_parser(vendor_id)
    ir = parser.parse(content)

    assert ir.metadata.hostname is not None
    assert ir.metadata.source_vendor == vendor_id
    assert len(ir.addresses) > 0
    assert len(ir.policies) > 0

    # 2. Optimize
    optimizer = RuleOptimizer(ir)
    unused = optimizer.find_unused_objects()
    assert isinstance(unused, dict)
    pruned_ir = optimizer.prune_unused_objects()
    assert pruned_ir is not None

    # 3. Generate for all registered targets
    for target_meta in PluginRegistry.list_target_vendors():
        target_id = target_meta['vendor_id']
        generator = PluginRegistry.get_generator(target_id)
        artifacts = generator.generate(ir)
        assert len(artifacts) > 0
        for art in artifacts:
            assert art.filename is not None
            assert len(art.content) > 0
