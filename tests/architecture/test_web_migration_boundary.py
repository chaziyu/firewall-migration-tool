import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
WEB_PATHS = (
    ROOT / "src" / "fwmigrate" / "web.py",
    *(ROOT / "src" / "fwmigrate" / "web_api").glob("*.py"),
)
PAIR_PACKAGE = "fwmigrate.conversion.fortigate_to_palo_alto"
APPLICATION_FACADE = f"{PAIR_PACKAGE}.application"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_web_uses_pair_application_facade_for_migration_semantics():
    violations = {}
    for path in WEB_PATHS:
        pair_imports = {
            name for name in _imports(path)
            if name == PAIR_PACKAGE or name.startswith(f"{PAIR_PACKAGE}.")
        }
        forbidden = pair_imports - {APPLICATION_FACADE}
        if forbidden:
            violations[str(path.relative_to(ROOT))] = sorted(forbidden)

    assert not violations, violations


def test_web_composition_root_delegates_migration_and_deployment_routes():
    source = (ROOT / "src" / "fwmigrate" / "web.py").read_text(encoding="utf-8")

    assert "register_migration_routes(app, signing_key)" in source
    assert "register_deployment_routes(app, signing_key, deployment_coordinator)" in source
    assert "@app.route('/api/migration/" not in source
    assert "@app.route('/api/deploy'" not in source
    assert "@app.route('/api/validate-candidate'" not in source
    assert "@app.route('/api/commit'" not in source
