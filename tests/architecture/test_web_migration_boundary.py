import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
WEB_PATHS = (
    ROOT / "src" / "fwmigrate" / "web.py",
    *(ROOT / "src" / "fwmigrate" / "web_api").glob("*.py"),
)
PAIR_PACKAGES = (
    "fwmigrate.conversion.fortigate_to_palo_alto",
    "fwmigrate.conversion.palo_alto_to_fortigate",
    "fwmigrate.conversion.fortigate_to_juniper_srx",
    "fwmigrate.conversion.fortigate_to_cisco_asa",
    "fwmigrate.conversion.fortigate_to_checkpoint",
    "fwmigrate.conversion.palo_alto_to_juniper_srx",
    "fwmigrate.conversion.palo_alto_to_cisco_asa",
    "fwmigrate.conversion.palo_alto_to_checkpoint",
    "fwmigrate.conversion.palo_alto_to_cisco_ftd",
)


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
            if any(name == package or name.startswith(f"{package}.") for package in PAIR_PACKAGES)
        }
        forbidden = pair_imports - {f"{package}.application" for package in PAIR_PACKAGES}
        if forbidden:
            violations[str(path.relative_to(ROOT))] = sorted(forbidden)

    assert not violations, violations


def test_web_composition_root_delegates_migration_and_deployment_routes():
    source = (ROOT / "src" / "fwmigrate" / "web.py").read_text(encoding="utf-8")

    assert "register_migration_routes(" in source
    assert "register_palo_alto_to_fortigate_routes(" in source
    assert "register_fortigate_to_checkpoint_routes(" in source
    assert "migration_planner_registry=migration_planners" in source
    assert "object_reuse_classifier=classify_target_object_reuse" in source
    assert "register_deployment_routes(" in source
    assert "deployment_coordinator" in source
    assert "deployer_factory=lambda options: PANSSHDeployer(options)" in source
    assert "@app.route('/api/migration/" not in source
    assert "@app.route('/api/deploy'" not in source
    assert "@app.route('/api/validate-candidate'" not in source
    assert "@app.route('/api/commit'" not in source
