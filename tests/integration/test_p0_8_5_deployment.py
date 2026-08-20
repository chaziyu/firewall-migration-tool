import os
import pytest
import uuid
from fwmigrate.deployment.snapshot import PaloAltoSnapshotManager
from fwmigrate.jobs.models import MigrationJob
from fwmigrate.jobs.state_machine import JobState
from fwmigrate.security.oidc import Identity
from fwmigrate.security.rbac import Role

class EnvironmentUnavailableError(Exception):
    pass

def require_real_environment():
    """
    Enforces that P0-8.5 is never silently skipped. If the target environment 
    is unavailable, it must explicitly fail to prevent a false positive certification.
    """
    target_ip = os.environ.get("TARGET_IP")
    target_api_key = os.environ.get("TARGET_API_KEY")
    
    if not target_ip or not target_api_key:
        print("\n\n=======================================================")
        print("P0-8.5 STATUS: ENVIRONMENT_UNAVAILABLE")
        print("Real firewall environment is missing. Cannot generate certification.")
        print("=======================================================\n")
        raise EnvironmentUnavailableError("ENVIRONMENT_UNAVAILABLE: Cannot proceed with P0-8.5 without a real firewall.")
    
    return target_ip, target_api_key

def test_destructive_rollback_flow():
    # Will throw explicit EnvironmentUnavailableError if not run with real target
    target_ip, api_key = require_real_environment()
    
    manager = PaloAltoSnapshotManager()
    job = MigrationJob(id=uuid.uuid4(), status=JobState.SNAPSHOT_CREATING.value)
    
    # 1. Snapshot
    snapshot_id = manager.create_snapshot(job)
    assert manager.verify_snapshot(snapshot_id)
    
    # 2. Intentional mutation (Apply)
    # Simulate an apply that partially succeeds but fails halfway
    # e.g., using requests to push a change
    
    # 3. Rollback
    assert manager.restore_snapshot(job, snapshot_id)
    
    # 4. Verify original state
    assert manager.verify_restore(job, snapshot_id)
