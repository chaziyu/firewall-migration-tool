import importlib
from pathlib import Path
import tomllib


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_job_models_are_importable():
    module = importlib.import_module("fwmigrate.jobs.models")

    assert module.MigrationJob.__tablename__ == "migration_jobs"


def test_dependency_ownership_is_declared_in_project_metadata():
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)["project"]

    runtime_dependencies = project["dependencies"]
    optional_dependencies = project["optional-dependencies"]

    assert "sqlalchemy>=2.0,<3.0" in runtime_dependencies
    assert "openpyxl>=3.1.0" not in runtime_dependencies
    assert "openpyxl>=3.1.0" in optional_dependencies["dev"]
    assert "openpyxl>=3.1.0" in optional_dependencies["reports"]
