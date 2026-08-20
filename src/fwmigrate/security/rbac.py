from enum import Enum

class Role(str, Enum):
    VIEWER = "VIEWER"
    ENGINEER = "ENGINEER"
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"
    PRODUCTION_APPROVER = "PRODUCTION_APPROVER"
    ADMIN = "ADMIN"

class Action(str, Enum):
    VIEW_JOB = "view_job"
    UPLOAD_CONFIG = "upload_config"
    START_MIGRATION = "start_migration"
    VALIDATE = "validate"
    APPROVE = "approve"
    PRODUCTION_APPLY = "production_apply"
    ROLLBACK = "rollback"
    MANAGE_USERS = "manage_users"
