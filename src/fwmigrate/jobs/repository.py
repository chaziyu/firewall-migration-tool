import uuid
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fwmigrate.jobs.models import MigrationJob, MigrationRevision, MigrationExecution, MigrationIssue, MigrationArtifactRecord

class JobRepositoryError(Exception):
    pass

class JobRepository:
    """
    Handles persistence of migration jobs and their child models.
    """
    def __init__(self, db_session: Session):
        self.db = db_session

    def create_job(self, created_by: str, source_vendor: str = None, target_vendor: str = None) -> MigrationJob:
        try:
            job = MigrationJob(created_by=created_by, source_vendor=source_vendor, target_vendor=target_vendor)
            self.db.add(job)
            self.db.commit()
            self.db.refresh(job)
            return job
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to create job: {str(e)}")

    def get_job(self, job_id: uuid.UUID) -> Optional[MigrationJob]:
        return self.db.query(MigrationJob).filter(MigrationJob.id == job_id).first()
        
    def get_job_with_lock(self, job_id: uuid.UUID) -> Optional[MigrationJob]:
        """Fetches the job using SELECT FOR UPDATE to acquire a DB-level row lock."""
        return self.db.query(MigrationJob).filter(MigrationJob.id == job_id).with_for_update().first()

    def update_job(self, job: MigrationJob) -> MigrationJob:
        try:
            self.db.commit()
            self.db.refresh(job)
            return job
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to update job: {str(e)}")

    def create_revision(self, job_id: uuid.UUID, revision_number: int) -> MigrationRevision:
        try:
            revision = MigrationRevision(job_id=job_id, revision_number=revision_number)
            self.db.add(revision)
            self.db.commit()
            self.db.refresh(revision)
            return revision
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to create revision: {str(e)}")

    def create_execution(self, job_id: uuid.UUID, revision_id: uuid.UUID, executor: str, approved_revision: uuid.UUID) -> MigrationExecution:
        try:
            execution = MigrationExecution(
                job_id=job_id, 
                revision_id=revision_id, 
                executor=executor,
                execution_status="STARTED",
                approved_revision=approved_revision
            )
            self.db.add(execution)
            self.db.commit()
            self.db.refresh(execution)
            return execution
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to create execution: {str(e)}")

    def add_issue(self, issue: MigrationIssue):
        try:
            self.db.add(issue)
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to add issue: {str(e)}")

    def get_issues(self, job_id: uuid.UUID, blocking_only: bool = False) -> List[MigrationIssue]:
        query = self.db.query(MigrationIssue).filter(MigrationIssue.job_id == job_id)
        if blocking_only:
            query = query.filter(MigrationIssue.blocking == True, MigrationIssue.status == 'OPEN')
        return query.all()
        
    def link_artifact(self, artifact_record: MigrationArtifactRecord):
        try:
            self.db.add(artifact_record)
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise JobRepositoryError(f"Failed to link artifact: {str(e)}")
