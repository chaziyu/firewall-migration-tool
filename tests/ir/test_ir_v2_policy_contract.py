from fwmigrate.ir import (
    IRAccessRole,
    IRAuthenticationPolicy,
    IRAuthenticationProfile,
    IRAuthenticationRule,
    IRAuthenticationScheme,
    IRCheckpointAccessRole,
    IRCheckpointIdentitySource,
    IRIdentitySource,
    IRPolicy,
    IRSecurityPolicy,
)


def test_legacy_policy_and_identity_python_names_are_aliases():
    assert IRPolicy is IRSecurityPolicy
    assert IRCheckpointIdentitySource is IRIdentitySource
    assert IRCheckpointAccessRole is IRAccessRole
    assert IRAuthenticationScheme is IRAuthenticationProfile
    assert IRAuthenticationRule is IRAuthenticationPolicy
