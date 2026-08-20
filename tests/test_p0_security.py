import pytest
from fwmigrate.security.oidc import Identity
from fwmigrate.security.rbac import Role, Action
from fwmigrate.security.authorization import AuthorizationEngine

def test_authorization_default_deny():
    engine = AuthorizationEngine()
    
    # Unauthenticated user should be denied everything
    unauth_user = Identity(user_id="u1", email="u1@test", name="U1", claims={}, roles=[], is_authenticated=False)
    assert not engine.is_authorized(unauth_user, Action.VIEW_JOB)
    
    # Authenticated but no roles
    auth_no_roles = Identity(user_id="u2", email="u2@test", name="U2", claims={}, roles=[], is_authenticated=True)
    assert not engine.is_authorized(auth_no_roles, Action.VIEW_JOB)

def test_authorization_rbac_matrix():
    engine = AuthorizationEngine()
    
    viewer = Identity(user_id="viewer1", email="viewer1@test", name="Viewer", claims={}, roles=[Role.VIEWER], is_authenticated=True)
    engineer = Identity(user_id="eng1", email="eng1@test", name="Eng", claims={}, roles=[Role.ENGINEER], is_authenticated=True)
    approver = Identity(user_id="app1", email="app1@test", name="App", claims={}, roles=[Role.APPROVER], is_authenticated=True)
    
    # Viewer can only view
    assert engine.is_authorized(viewer, Action.VIEW_JOB)
    assert not engine.is_authorized(viewer, Action.START_MIGRATION)
    
    # Engineer can start but not approve
    assert engine.is_authorized(engineer, Action.START_MIGRATION)
    assert not engine.is_authorized(engineer, Action.APPROVE)
    
    # Approver can approve
    assert engine.is_authorized(approver, Action.APPROVE)

class DummyJobContext:
    def __init__(self, created_by=None, approved_by=None):
        self.created_by = created_by
        self.approved_by = approved_by

def test_separation_of_duties():
    engine = AuthorizationEngine()
    
    approver = Identity(user_id="user123", email="user123@test", name="User", claims={}, roles=[Role.APPROVER, Role.ENGINEER], is_authenticated=True)
    
    # Approver can approve a job they didn't create
    other_job = DummyJobContext(created_by="someone_else")
    assert engine.is_authorized(approver, Action.APPROVE, context=other_job)
    
    # Approver CANNOT approve their own job
    own_job = DummyJobContext(created_by="user123")
    assert not engine.is_authorized(approver, Action.APPROVE, context=own_job)
    
    admin = Identity(user_id="admin1", email="admin1@test", name="Admin", claims={}, roles=[Role.ADMIN], is_authenticated=True)
    
    # Admin can bypass separation of duties
    admin_job = DummyJobContext(created_by="admin1")
    assert engine.is_authorized(admin, Action.APPROVE, context=admin_job)
