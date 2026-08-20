import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Integer, Boolean, Text
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()

class MigrationJob(Base):
    __tablename__ = 'migration_jobs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status = Column(String(50), nullable=False, default='CREATED')
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Source context
    source_vendor = Column(String(50))
    source_product = Column(String(50))
    source_version = Column(String(50))
    source_deployment_model = Column(String(50))
    
    # Target context
    target_vendor = Column(String(50))
    target_product = Column(String(50))
    target_version = Column(String(50))
    target_deployment_model = Column(String(50))
    
    # Artifact hashes at job level (typically latest approved)
    source_artifact_hash = Column(String(64))
    native_model_hash = Column(String(64))
    ir_hash = Column(String(64))
    target_artifact_hash = Column(String(64))
    validation_result_hash = Column(String(64))
    plan_hash = Column(String(64))
    snapshot_hash = Column(String(64))
    approval_hash = Column(String(64))
    
    risk_score_numeric = Column(Integer)
    risk_level = Column(String(20)) # LOW, MEDIUM, HIGH, CRITICAL
    
    current_revision = Column(UUID(as_uuid=True), ForeignKey('migration_revisions.id', use_alter=True))
    
    error_code = Column(String(50))
    error_message = Column(Text)
    
    approved_by = Column(String(100))
    approved_at = Column(DateTime(timezone=True))
    executed_by = Column(String(100))
    executed_at = Column(DateTime(timezone=True))

    revisions = relationship("MigrationRevision", foreign_keys="MigrationRevision.job_id", back_populates="job")
    executions = relationship("MigrationExecution", back_populates="job")
    issues = relationship("MigrationIssue", back_populates="job")


class MigrationRevision(Base):
    __tablename__ = 'migration_revisions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey('migration_jobs.id'), nullable=False)
    revision_number = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    source_artifact_hash = Column(String(64))
    native_model_hash = Column(String(64))
    ir_hash = Column(String(64))
    target_artifact_hash = Column(String(64))
    validation_result_hash = Column(String(64))
    plan_hash = Column(String(64))
    
    job = relationship("MigrationJob", foreign_keys=[job_id], back_populates="revisions")


class MigrationExecution(Base):
    __tablename__ = 'migration_executions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey('migration_jobs.id'), nullable=False)
    revision_id = Column(UUID(as_uuid=True), ForeignKey('migration_revisions.id'), nullable=False)
    
    execution_status = Column(String(50))
    executor = Column(String(100))
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True))
    
    approved_revision = Column(UUID(as_uuid=True))
    approved_artifact_hash = Column(String(64))
    approved_ir_hash = Column(String(64))
    approved_plan_hash = Column(String(64))
    executed_artifact_hash = Column(String(64))
    snapshot_id = Column(String(100))
    rollback_status = Column(String(50))
    result = Column(Text)
    
    # Worker leases for recovery
    worker_id = Column(String(100))
    heartbeat_at = Column(DateTime(timezone=True))
    lease_expires_at = Column(DateTime(timezone=True))
    
    job = relationship("MigrationJob", back_populates="executions")


class MigrationIssue(Base):
    __tablename__ = 'migration_issues'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey('migration_jobs.id'), nullable=False)
    
    severity = Column(String(20)) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), default='OPEN') # OPEN, RESOLVED
    category = Column(String(50))
    
    source_object = Column(String(255))
    target_object = Column(String(255))
    
    message = Column(Text)
    recommended_action = Column(Text)
    blocking = Column(Boolean, default=False)
    
    resolved_by = Column(String(100))
    resolved_at = Column(DateTime(timezone=True))
    
    job = relationship("MigrationJob", back_populates="issues")


class MigrationJobEvent(Base):
    __tablename__ = 'migration_job_events'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey('migration_jobs.id'), nullable=False)
    execution_id = Column(UUID(as_uuid=True), ForeignKey('migration_executions.id'), nullable=True)
    
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    actor = Column(String(100))
    action = Column(String(50))
    old_state = Column(String(50))
    new_state = Column(String(50))
    details = Column(Text)

class MigrationArtifactRecord(Base):
    """
    Database record pointing to actual artifact files in the Artifact Store.
    """
    __tablename__ = 'migration_artifacts'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey('migration_jobs.id'), nullable=False)
    revision_id = Column(UUID(as_uuid=True), ForeignKey('migration_revisions.id'), nullable=True)
    
    sha256 = Column(String(64), nullable=False)
    artifact_type = Column(String(50)) # source_config, native_model, target_artifact, plan, validation_report
    location = Column(String(512), nullable=False) # object store URI or path
    encryption_status = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True))
