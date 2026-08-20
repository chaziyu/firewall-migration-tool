import uuid
from typing import Optional
from sqlalchemy.orm import Session
from fwmigrate.jobs.models import MigrationJobEvent

class AuditLogger:
    """
    Records immutable audit events for state transitions and critical actions.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
        
    def log_event(self, job_id: uuid.UUID, actor: str, action: str, 
                  old_state: Optional[str] = None, new_state: Optional[str] = None, 
                  execution_id: Optional[uuid.UUID] = None, details: Optional[str] = None):
        """
        Creates and persists a new MigrationJobEvent.
        """
        event = MigrationJobEvent(
            job_id=job_id,
            execution_id=execution_id,
            actor=actor,
            action=action,
            old_state=old_state,
            new_state=new_state,
            details=details
        )
        self.db.add(event)
        self.db.commit()
        return event
