"""Public discovery for implemented directional migration workflows."""

from fwmigrate.conversion.workflow_registry import migration_workflows


def register_migration_pair_routes(app, workflow_registry=migration_workflows) -> None:
    @app.get("/api/migration/pairs")
    def migration_pairs():
        return {
            "success": True,
            "pairs": [workflow.public_metadata() for workflow in workflow_registry.list()],
        }
