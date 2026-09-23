from pathlib import Path
import json

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_management_objects_rules_and_domains_are_extracted():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    result = extract_checkpoint_source(source)
    config = result.config
    assert config.hosts and config.access_rules
    assert all(item.source_plane == "management" for item in config.hosts)
    assert {(item.domain_uid, item.name) for item in config.hosts} >= {
        ("domain-a", "SharedName"),
        ("domain-b", "SharedName"),
    }
    assert len(result.derived.references.by_name[("domain-a", "SharedName")]) == 1
    assert len(result.derived.references.by_name[("domain-b", "SharedName")]) == 1


def test_live_identity_commands_feed_typed_collections_and_relationships():
    source = json.dumps({"responses": [
        {"command": "show-users", "data": {"objects": [{"uid": "u", "name": "alice", "type": "user", "groups": ["g"]}]}},
        {"command": "show-user-groups", "data": {"objects": [{"uid": "g", "name": "ops", "type": "user-group", "users": ["u"]}]}},
        {"command": "show-access-roles", "data": {"objects": [{"uid": "r", "name": "role", "type": "access-role", "users": ["u"], "groups": ["g"]}]}},
        {"command": "show-permission-profiles", "data": {"objects": [{"uid": "p", "name": "profile", "type": "permission-profile"}]}},
        {"command": "show-administrators", "data": {"objects": [{"uid": "a", "name": "admin", "type": "administrator", "permission-profiles": ["p"]}]}},
    ]})
    result = extract_checkpoint_source(source)
    assert result.config.users and result.config.user_groups and result.config.access_roles
    assert result.config.permission_profiles and result.config.administrators
    identity = result.derived.identity
    assert any(edge.owner.name == "alice" and edge.resolved_target.name == "ops" for edge in identity.memberships)
    assert {edge.field for edge in identity.access_roles} == {"users", "groups"}
    assert {edge.target.name for edge in identity.access_roles} == {"alice", "ops"}
    assert identity.administrator_permissions[0].permission_profile.name == "profile"
