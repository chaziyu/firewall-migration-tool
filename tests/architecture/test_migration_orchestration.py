from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_cli_and_web_call_migration_pipeline():
    main = (ROOT / "src/fwmigrate/main.py").read_text(encoding="utf-8")
    web = (ROOT / "src/fwmigrate/web.py").read_text(encoding="utf-8")

    assert "MigrationPipeline().run" in main
    assert "MigrationPipeline().run" in web
    assert "PANOSTerraformGenerator" not in web
    assert "PluginRegistry.get_generator" not in web


def test_adapters_do_not_call_legacy_normalization_wrapper():
    main = (ROOT / "src/fwmigrate/main.py").read_text(encoding="utf-8")
    web = (ROOT / "src/fwmigrate/web.py").read_text(encoding="utf-8")

    assert "fix_outbound_threat_source_anomalies" not in main
    assert "fix_outbound_threat_source_anomalies" not in web
