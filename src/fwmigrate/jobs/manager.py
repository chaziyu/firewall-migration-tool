import uuid
from typing import Optional
from sqlalchemy.orm import Session
from fwmigrate.jobs.models import MigrationJob, MigrationExecution, MigrationRevision, MigrationIssue
from fwmigrate.jobs.repository import JobRepository
from fwmigrate.jobs.state_machine import StateMachine, JobState, InvalidStateTransitionError
from fwmigrate.jobs.events import AuditLogger
from fwmigrate.security.oidc import Identity
from fwmigrate.security.authorization import AuthorizationEngine, Action

class JobManager:
    """
    Orchestrates the lifecycle of a migration job.
    Enforces state transitions, authorization, and audit logging.
    """
    
    def __init__(self, db_session: Session, auth_engine: AuthorizationEngine = None):
        self.repo = JobRepository(db_session)
        self.audit = AuditLogger(db_session)
        self.auth = auth_engine or AuthorizationEngine()
        
    def _guard_transition(self, job: MigrationJob, target_state: JobState, identity: Identity):
        """Validates that a transition is authorized and valid."""
        # 1. State machine transition check
        current_state = JobState(job.status)
        StateMachine.transition(current_state, target_state)
        
        # 2. Authorization check (Example: Only approvers can move to APPROVED)
        action_map = {
            JobState.APPROVED: Action.APPROVE,
            JobState.APPLYING: Action.PRODUCTION_APPLY,
            JobState.VALIDATING: Action.VALIDATE,
            JobState.ROLLBACK_PENDING: Action.ROLLBACK,
        }
        
        required_action = action_map.get(target_state, Action.START_MIGRATION)
        if not self.auth.is_authorized(identity, required_action, context=job):
            raise PermissionError(f"User {identity.user_id} not authorized to transition job to {target_state}")

    def create_job(self, identity: Identity, source_vendor: str, target_vendor: str) -> MigrationJob:
        if not self.auth.is_authorized(identity, Action.START_MIGRATION):
            raise PermissionError("Not authorized to create jobs")
            
        job = self.repo.create_job(identity.user_id, source_vendor, target_vendor)
        self.audit.log_event(job.id, identity.user_id, "CREATE_JOB", new_state=JobState.CREATED)
        return job

    def update_job_state(self, job_id: uuid.UUID, target_state: JobState, identity: Identity, details: str = None) -> MigrationJob:
        """Transitions job to a new state with full locking and audit."""
        job = self.repo.get_job_with_lock(job_id)
        if not job:
            raise ValueError("Job not found")
            
        old_state = job.status
        self._guard_transition(job, target_state, identity)
        
        job.status = target_state.value
        
        if target_state == JobState.APPROVED:
            job.approved_by = identity.user_id
            
            # Must verify that blocking issues are 0
            blocking_issues = self.repo.get_issues(job.id, blocking_only=True)
            if blocking_issues:
                raise ValueError(f"Cannot approve job {job.id} with {len(blocking_issues)} unresolved blocking issues")
        
        job = self.repo.update_job(job)
        self.audit.log_event(job.id, identity.user_id, "STATE_TRANSITION", old_state=old_state, new_state=target_state.value, details=details)
        return job

    def execute_job(self, job_id: uuid.UUID, identity: Identity, target_artifact_hash: str) -> MigrationExecution:
        """Starts a deployment execution. Requires job to be in SNAPSHOT_READY."""
        job = self.repo.get_job_with_lock(job_id)
        if not job:
            raise ValueError("Job not found")
            
        self._guard_transition(job, JobState.APPLYING, identity)
        
        if job.target_artifact_hash != target_artifact_hash:
            raise ValueError("Immutable execution context violation: Provided artifact hash does not match approved hash")
            
        execution = self.repo.create_execution(job.id, job.current_revision, identity.user_id, job.current_revision)
        
        job.status = JobState.APPLYING.value
        job.executed_by = identity.user_id
        self.repo.update_job(job)
        
        self.audit.log_event(job.id, identity.user_id, "EXECUTE_JOB", old_state=JobState.SNAPSHOT_READY.value, new_state=JobState.APPLYING.value, execution_id=execution.id)
        return execution
