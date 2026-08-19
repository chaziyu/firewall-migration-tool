import pytest
from pathlib import Path
from fg2pan.core.registry import PluginRegistry
from fg2pan.core.optimizer import RuleOptimizer

GOLDEN_CASES = [
    ("fortigate", "examples/example_fortigate.conf"),
    ("cisco_asa", "examples/example_cisco_asa.cfg"),
    ("checkpoint", "examples/example_checkpoint.json"),
    ("juniper_srx", "examples/example_juniper_srx.set"),
]

@pytest.mark.parametrize("vendor_id, file_path", GOLDEN_CASES)
def test_golden_parsing_and_generation(vendor_id, file_path):
    full_path = Path(file_path)
    assert full_path.exists(), f"Golden file {file_path} not found"

    with open(full_path, "r", encoding="utf-8") as f:
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
