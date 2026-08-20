import pytest
import uuid
from fwmigrate.jobs.models import MigrationJob, MigrationExecution
from fwmigrate.jobs.state_machine import JobState
from fwmigrate.security.oidc import Identity
from fwmigrate.security.rbac import Role
from fwmigrate.jobs.manager import JobManager
from fwmigrate.deployment.executor import DeploymentExecutor
from fwmigrate.deployment.snapshot import PaloAltoSnapshotManager
from fwmigrate.security.secrets import EphemeralCredentialMaterializer, get_secret_manager

# Mock SQLAlchemy session for integration flow without true DB in memory
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
        return [i for i in self.session.issues if i.job_id == job_id and (not blocking_only or i.blocking)]
        
    def update_job(self, job):
        self.session.jobs[job.id] = job
        return job
        
    def create_execution(self, job_id, rev_id, user_id, approved_rev):
        e = MigrationExecution(id=uuid.uuid4(), job_id=job_id, revision_id=rev_id, executor=user_id, approved_revision=approved_rev)
        self.session.add(e)
        return e

def test_end_to_end_artifact_hash_invariant(monkeypatch):
    session = MockSession()
    repo = MockRepo(session)
    
    manager = JobManager(session)
    # Monkeypatch repo
    manager.repo = repo
    
    executor = DeploymentExecutor(manager, PaloAltoSnapshotManager(), EphemeralCredentialMaterializer(get_secret_manager()))
    
    eng = Identity(user_id="eng1", email="eng@test", name="Eng", roles=[Role.ENGINEER, Role.PRODUCTION_APPROVER], is_authenticated=True, claims={})
    app = Identity(user_id="app1", email="app@test", name="App", roles=[Role.APPROVER], is_authenticated=True, claims={})
    
    # 1. Create Job
    job = manager.create_job(eng, "fortigate", "paloalto")
    
    # Fast forward to validation
    job.status = JobState.VALIDATING
    repo.update_job(job)
    
    # Set hashes
    job.target_artifact_hash = "hash_A"
    job.ir_hash = "hash_IR_A"
    job.plan_hash = "hash_PLAN_A"
    job.current_revision = uuid.uuid4()
    
    # 2. Review
    manager.update_job_state(job.id, JobState.REVIEW_REQUIRED, eng)
    
    # 3. Approve (as approver)
    manager.update_job_state(job.id, JobState.APPROVED, app)
    
    # 4. Plan
    manager.update_job_state(job.id, JobState.PLANNING, eng)
    manager.update_job_state(job.id, JobState.PLAN_READY, eng)
    
    # 5. Snapshot
    executor.prepare_deployment(job.id, eng)
    assert session.jobs[job.id].status == JobState.SNAPSHOT_READY.value
    
    # 6. Execute with WRONG hash
    with pytest.raises(ValueError, match="Immutable execution context violation"):
        executor.execute_deployment(job.id, eng, target_artifact_hash="hash_B")
        
    # State should not be applying
    assert session.jobs[job.id].status != JobState.APPLYING.value
    
    # 7. Execute with CORRECT hash
    executor.execute_deployment(job.id, eng, target_artifact_hash="hash_A")
    assert session.jobs[job.id].status == JobState.SUCCEEDED.value
