import ast
from pathlib import Path


WEB_PATH = Path(__file__).parents[2] / "src" / "fwmigrate" / "web.py"
PAIR_PACKAGE = "fwmigrate.conversion.fortigate_to_palo_alto."
FORBIDDEN_MODULES = {
    "auto_decisions",
    "decision_propagation",
    "requirements",
    "target_candidates",
    "target_validation",
    "review_context",
    "review_evidence",
    "review_workflow",
    "target_object_reuse",
}


def test_web_uses_pair_application_facade_for_migration_semantics():
    tree = ast.parse(WEB_PATH.read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    direct_pair_modules = {
        name.removeprefix(PAIR_PACKAGE).split(".", 1)[0]
        for name in imports
        if name and name.startswith(PAIR_PACKAGE)
        and name != f"{PAIR_PACKAGE}application"
    }
    assert not (direct_pair_modules & FORBIDDEN_MODULES)
