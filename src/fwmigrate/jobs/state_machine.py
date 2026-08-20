from enum import Enum

class JobState(str, Enum):
    CREATED = "CREATED"
    INGESTING = "INGESTING"
    INGESTED = "INGESTED"
    PARSING = "PARSING"
    PARSED = "PARSED"
    NORMALIZING = "NORMALIZING"
    NORMALIZED = "NORMALIZED"
    VALIDATING = "VALIDATING"
    
    BLOCKED = "BLOCKED" # Non-terminal: waiting for human resolution
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    
    REJECTED = "REJECTED" # Terminal
    APPROVED = "APPROVED"
    
    PLANNING = "PLANNING"
    PLAN_FAILED = "PLAN_FAILED" # Non-terminal or Terminal depending on retry config
    PLAN_READY = "PLAN_READY"
    
    SNAPSHOT_CREATING = "SNAPSHOT_CREATING"
    SNAPSHOT_FAILED = "SNAPSHOT_FAILED" # Non-terminal/Terminal
    SNAPSHOT_READY = "SNAPSHOT_READY"
    
    APPLYING = "APPLYING"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RECONCILING = "RECONCILING"
    RETRY_APPROVAL = "RETRY_APPROVAL"
    APPLY_FAILED = "APPLY_FAILED"
    
    VERIFYING = "VERIFYING"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    
    SUCCEEDED = "SUCCEEDED" # Terminal
    
    FAILED = "FAILED" # Terminal (general catch-all for errors not gracefully handled)
    CANCELLED = "CANCELLED" # Terminal
    EXPIRED = "EXPIRED" # Terminal
    
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK" # Terminal

# Valid transitions from a state
VALID_TRANSITIONS = {
    JobState.CREATED: [JobState.INGESTING, JobState.CANCELLED],
    JobState.INGESTING: [JobState.INGESTED, JobState.FAILED, JobState.CANCELLED],
    JobState.INGESTED: [JobState.PARSING, JobState.CANCELLED],
    JobState.PARSING: [JobState.PARSED, JobState.FAILED, JobState.CANCELLED],
    JobState.PARSED: [JobState.NORMALIZING, JobState.CANCELLED],
    JobState.NORMALIZING: [JobState.NORMALIZED, JobState.FAILED, JobState.CANCELLED],
    JobState.NORMALIZED: [JobState.VALIDATING, JobState.CANCELLED],
    JobState.VALIDATING: [JobState.REVIEW_REQUIRED, JobState.BLOCKED, JobState.FAILED, JobState.CANCELLED],
    JobState.BLOCKED: [JobState.VALIDATING, JobState.CANCELLED], # Can re-validate after fixes
    JobState.REVIEW_REQUIRED: [JobState.APPROVED, JobState.REJECTED, JobState.CANCELLED],
    JobState.APPROVED: [JobState.PLANNING, JobState.CANCELLED],
    JobState.PLANNING: [JobState.PLAN_READY, JobState.PLAN_FAILED, JobState.CANCELLED],
    JobState.PLAN_FAILED: [JobState.PLANNING, JobState.CANCELLED, JobState.FAILED],
    JobState.PLAN_READY: [JobState.SNAPSHOT_CREATING, JobState.CANCELLED],
    JobState.SNAPSHOT_CREATING: [JobState.SNAPSHOT_READY, JobState.SNAPSHOT_FAILED, JobState.CANCELLED],
    JobState.SNAPSHOT_FAILED: [JobState.SNAPSHOT_CREATING, JobState.CANCELLED, JobState.FAILED],
    JobState.SNAPSHOT_READY: [JobState.APPLYING, JobState.CANCELLED],
    JobState.APPLYING: [JobState.VERIFYING, JobState.APPLY_FAILED, JobState.RECOVERY_REQUIRED],
    JobState.RECOVERY_REQUIRED: [JobState.RECONCILING, JobState.FAILED],
    JobState.RECONCILING: [JobState.SUCCEEDED, JobState.RETRY_APPROVAL, JobState.ROLLBACK_PENDING, JobState.FAILED],
    JobState.RETRY_APPROVAL: [JobState.APPROVED, JobState.REJECTED, JobState.CANCELLED],
    JobState.APPLY_FAILED: [JobState.ROLLBACK_PENDING, JobState.FAILED],
    JobState.VERIFYING: [JobState.SUCCEEDED, JobState.VERIFICATION_FAILED],
    JobState.VERIFICATION_FAILED: [JobState.ROLLBACK_PENDING, JobState.FAILED],
    JobState.ROLLBACK_PENDING: [JobState.ROLLING_BACK, JobState.FAILED],
    JobState.ROLLING_BACK: [JobState.ROLLED_BACK, JobState.FAILED],
    
    # Terminal states
    JobState.REJECTED: [],
    JobState.SUCCEEDED: [],
    JobState.FAILED: [],
    JobState.CANCELLED: [],
    JobState.EXPIRED: [],
    JobState.ROLLED_BACK: [],
}

class InvalidStateTransitionError(Exception):
    pass

class StateMachine:
    @staticmethod
    def can_transition(current: JobState, target: JobState) -> bool:
        return target in VALID_TRANSITIONS.get(current, [])

    @staticmethod
    def transition(current: JobState, target: JobState) -> JobState:
        if not StateMachine.can_transition(current, target):
            raise InvalidStateTransitionError(f"Cannot transition from {current} to {target}")
        return target
