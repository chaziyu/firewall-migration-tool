import ast
from pathlib import Path


FORBIDDEN_SOURCE_TYPES = {
    "CheckPointIPPool",
    "CheckPointVIP",
    "CheckPointVIPGroup",
    "CheckPointProfileGroup",
    "CheckPointSDWAN",
}
EXPECTED_DERIVED_TYPES = {
    "CPNATMigrationView",
    "CPVPNMigrationView",
    "CPInterfaceView",
}


def _declared_classes(directory: Path) -> set[str]:
    return {
        node.name
        for path in directory.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ClassDef)
    }


def test_check_point_source_and_transform_modules_do_not_add_fake_source_types():
    repository = Path(__file__).parents[3]
    checkpoint = repository / "src" / "fwmigrate" / "vendors" / "checkpoint"
    model_classes = _declared_classes(checkpoint / "model")
    transform_classes = _declared_classes(checkpoint / "transform")

    assert not (model_classes | transform_classes) & FORBIDDEN_SOURCE_TYPES
    assert EXPECTED_DERIVED_TYPES <= transform_classes
    assert not any(name.startswith("CheckPoint") for name in transform_classes)
