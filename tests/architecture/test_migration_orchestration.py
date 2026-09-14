import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]


def _tree(name):
    return ast.parse((ROOT / "src" / "fwmigrate" / name).read_text(encoding="utf-8"))


def _method_calls(tree, method):
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
    ]


def test_user_facing_migration_adapters_delegate_to_pipeline():
    for name in ("main.py", "web.py"):
        tree = _tree(name)
        assert any(
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "MigrationPipeline"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        )


def test_adapters_do_not_directly_generate_target_artifacts_or_repair_rules():
    for name in ("main.py", "web.py"):
        tree = _tree(name)
        assert not any(
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "fix_outbound_threat_source_anomalies"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        )
    web_source = (ROOT / "src" / "fwmigrate" / "web.py").read_text(encoding="utf-8")
    assert "PANOSTerraformGenerator" not in web_source
    assert "PluginRegistry.get_generator" not in web_source


def test_live_source_paths_remain_collection_only():
    for name in ("live_source_cli.py", "live_source_api.py"):
        source = (ROOT / "src" / "fwmigrate" / name).read_text(encoding="utf-8")
        assert "PluginRegistry.get_generator" not in source


def test_central_safety_boundary_is_in_pipeline_only():
    pipeline_source = (ROOT / "src" / "fwmigrate" / "application" / "pipeline.py").read_text(encoding="utf-8")
    assert "evaluate_extraction" in pipeline_source
    assert "evaluate_pre_generation" in pipeline_source
    for name in ("main.py", "web.py"):
        source = (ROOT / "src" / "fwmigrate" / name).read_text(encoding="utf-8")
        assert "generation_safe" not in source
        assert "generation_blocking_reasons" not in source
