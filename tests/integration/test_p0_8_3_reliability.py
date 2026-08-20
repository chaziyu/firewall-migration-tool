import pytest
import uuid
import datetime
import multiprocessing
import time
from unittest.mock import patch
from fwmigrate.jobs.models import MigrationJob, MigrationExecution
from fwmigrate.jobs.state_machine import JobState, StateMachine
from fwmigrate.security.oidc import Identity
from fwmigrate.security.rbac import Role
from fwmigrate.jobs.manager import JobManager
from fwmigrate.deployment.executor import DeploymentExecutor
from fwmigrate.deployment.snapshot import PaloAltoSnapshotManager
from fwmigrate.security.secrets import EphemeralCredentialMaterializer, get_secret_manager

# Mock SQLAlchemy session
class MockSession:
    def __init__(self):
        self.jobs = {}
        self.executions = {}
        self.issues = []
        self.events = []
    
    def add(self, obj):
        if isinstance(obj, MigrationJob):
            self.jobs[obj.id] = obj
        elif isinstance(obj, MigrationExecution):
            self.executions[obj.id] = obj
        elif type(obj).__name__ == "MigrationIssue":
            self.issues.append(obj)
        elif type(obj).__name__ == "MigrationJobEvent":
            self.events.append(obj)
            
    def commit(self):
        pass
        
    def refresh(self, obj):
        pass
        
class MockRepo:
    def __init__(self, session):
        self.session = session
        
    def create_job(self, user_id, src, tgt):
        job = MigrationJob(id=uuid.uuid4(), created_by=user_id, source_vendor=src, target_vendor=tgt)
        self.session.add(job)
        return job
        
    def get_job_with_lock(self, job_id):
        return self.session.jobs.get(job_id)
        
    def get_issues(self, job_id, blocking_only=False):
        return []
        
    def update_job(self, job):
        self.session.jobs[job.id] = job
        return job
        
    def create_execution(self, job_id, rev_id, user_id, approved_rev):
        e = MigrationExecution(id=uuid.uuid4(), job_id=job_id, revision_id=rev_id, executor=user_id, approved_revision=approved_rev)
        
        # Simulating lease assignment
        e.worker_id = "worker-1"
        e.heartbeat_at = datetime.datetime.now(datetime.timezone.utc)
        e.lease_expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        
        self.session.add(e)
        return e

def test_worker_crash_recovery_transitions():
    session = MockSession()
    repo = MockRepo(session)
    manager = JobManager(session)
    manager.repo = repo
    
    # 1. Setup job in APPLYING state
    job = repo.create_job("eng1", "cisco", "panos")
    job.status = JobState.APPLYING.value
    repo.update_job(job)
    
    # Execution representation
    exec_id = uuid.uuid4()
    execution = MigrationExecution(
        id=exec_id, 
        job_id=job.id, 
        revision_id=uuid.uuid4(), 
        worker_id="worker-1",
        heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10),
        lease_expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5) # Expired lease
    )
    session.add(execution)
    
    eng = Identity(user_id="eng1", email="eng@test", name="Eng", roles=[Role.ENGINEER, Role.OPERATOR], is_authenticated=True, claims={})
    
    # 2. Worker 2 detects expired lease during APPLYING. Needs to move to RECOVERY_REQUIRED.
    # We use update_job_state directly for this transition
    manager.update_job_state(job.id, JobState.RECOVERY_REQUIRED, eng)
    assert session.jobs[job.id].status == JobState.RECOVERY_REQUIRED.value
    
    # 3. Move to RECONCILING
    manager.update_job_state(job.id, JobState.RECONCILING, eng)
    assert session.jobs[job.id].status == JobState.RECONCILING.value
    
    # 4. Depending on target state check, it either goes to SUCCEEDED, ROLLBACK_PENDING, or RETRY_APPROVAL
    # Here we mock it found inconsistent state -> ROLLBACK_PENDING
    manager.update_job_state(job.id, JobState.ROLLBACK_PENDING, eng)
    assert session.jobs[job.id].status == JobState.ROLLBACK_PENDING.value
