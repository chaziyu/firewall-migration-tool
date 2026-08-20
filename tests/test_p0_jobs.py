import pytest
from fwmigrate.jobs.state_machine import StateMachine, JobState, InvalidStateTransitionError

def test_valid_state_transitions():
    # Happy path to planning
    assert StateMachine.transition(JobState.CREATED, JobState.INGESTING) == JobState.INGESTING
    assert StateMachine.transition(JobState.INGESTING, JobState.INGESTED) == JobState.INGESTED
    assert StateMachine.transition(JobState.VALIDATING, JobState.REVIEW_REQUIRED) == JobState.REVIEW_REQUIRED
    assert StateMachine.transition(JobState.REVIEW_REQUIRED, JobState.APPROVED) == JobState.APPROVED
    assert StateMachine.transition(JobState.APPROVED, JobState.PLANNING) == JobState.PLANNING
    
    # Rollback path
    assert StateMachine.transition(JobState.APPLY_FAILED, JobState.ROLLBACK_PENDING) == JobState.ROLLBACK_PENDING
    assert StateMachine.transition(JobState.ROLLBACK_PENDING, JobState.ROLLING_BACK) == JobState.ROLLING_BACK
    assert StateMachine.transition(JobState.ROLLING_BACK, JobState.ROLLED_BACK) == JobState.ROLLED_BACK

def test_invalid_state_transitions():
    with pytest.raises(InvalidStateTransitionError):
        # Cannot skip approval
        StateMachine.transition(JobState.REVIEW_REQUIRED, JobState.PLANNING)
        
    with pytest.raises(InvalidStateTransitionError):
        # Cannot apply if not ready
        StateMachine.transition(JobState.CREATED, JobState.APPLYING)
        
    with pytest.raises(InvalidStateTransitionError):
        # Cannot modify a terminal state
        StateMachine.transition(JobState.SUCCEEDED, JobState.PLANNING)
        
    with pytest.raises(InvalidStateTransitionError):
        # Cannot approve directly after planning (wrong direction)
        StateMachine.transition(JobState.PLANNING, JobState.APPROVED)
