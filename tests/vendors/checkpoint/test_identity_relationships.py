from fwmigrate.vendors.checkpoint.model.address import CPNetwork
from fwmigrate.vendors.checkpoint.model.administration import CPAdministrator, CPPermissionProfile
from fwmigrate.vendors.checkpoint.model.identity import CPAccessRole, CPUser, CPUserGroup
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.identity import build_identity_relationships


def test_identity_relationships_keep_permission_and_role_edges_separate():
    profile = CPPermissionProfile(uid="p", name="profile")
    admin = CPAdministrator(uid="a", name="admin", permission_profiles=["p"])
    user = CPUser(uid="u", name="user", groups=["g"])
    group = CPUserGroup(uid="g", name="group", users=["u"])
    network = CPNetwork(uid="n", name="network")
    role = CPAccessRole(uid="r", name="role", networks=["n"], users=["u"], groups=["g"])
    identity = build_identity_relationships(CheckPointConfig(permission_profiles=[profile], administrators=[admin], users=[user], user_groups=[group], networks=[network], access_roles=[role]))
    assert identity.administrator_permissions[0].permission_profile is profile
    assert {edge.source_field for edge in identity.memberships} == {"groups", "users"}
    assert {edge.field for edge in identity.access_roles} == {"networks", "users", "groups"}
