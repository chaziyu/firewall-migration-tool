from typing import Dict, List, Any
from fwmigrate.security.rbac import Role, Action
from fwmigrate.security.oidc import Identity

# Default Deny: Actions not in this list are denied. Roles not listed for an action are denied.
DEFAULT_AUTH_MATRIX: Dict[Action, List[Role]] = {
    Action.VIEW_JOB: [Role.VIEWER, Role.ENGINEER, Role.OPERATOR, Role.APPROVER, Role.PRODUCTION_APPROVER, Role.ADMIN],
    Action.UPLOAD_CONFIG: [Role.ENGINEER, Role.OPERATOR, Role.ADMIN],
    Action.START_MIGRATION: [Role.ENGINEER, Role.OPERATOR, Role.ADMIN],
    Action.VALIDATE: [Role.ENGINEER, Role.OPERATOR, Role.APPROVER, Role.PRODUCTION_APPROVER, Role.ADMIN],
    Action.APPROVE: [Role.APPROVER, Role.PRODUCTION_APPROVER, Role.ADMIN],
    Action.PRODUCTION_APPLY: [Role.PRODUCTION_APPROVER, Role.ADMIN],
    Action.ROLLBACK: [Role.OPERATOR, Role.PRODUCTION_APPROVER, Role.ADMIN],
    Action.MANAGE_USERS: [Role.ADMIN]
}

class AuthorizationEngine:
    """
    Evaluates whether an identity is allowed to perform a specific action on a job context.
    """
    def __init__(self, matrix: Dict[Action, List[Role]] = DEFAULT_AUTH_MATRIX):
        self.matrix = matrix

    def is_authorized(self, identity: Identity, action: Action, context: Any = None) -> bool:
        """
        Check if the identity is authorized to perform the action.
        The `context` allows for fine-grained checks (e.g., job creator cannot be job approver).
        """
        if not identity.is_authenticated:
            return False
            
        allowed_roles = self.matrix.get(action, [])
        
        # Base role check
        has_role = any(role in allowed_roles for role in identity.roles)
        if not has_role:
            return False
            
        # Additional context checks (Separation of Duties)
        if action == Action.APPROVE and context:
            # e.g., if context has created_by
            created_by = getattr(context, 'created_by', None)
            if created_by == identity.user_id:
                # Unless admin, cannot approve own job
                if Role.ADMIN not in identity.roles:
                    return False
                    
        if action == Action.PRODUCTION_APPLY and context:
            # e.g., if context has approved_by
            approved_by = getattr(context, 'approved_by', None)
            if approved_by == identity.user_id:
                # Unless admin, cannot apply own approved job
                if Role.ADMIN not in identity.roles:
                    return False

        return True
