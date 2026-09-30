from dataclasses import fields
from inspect import getsource

from fwmigrate.deployment import PANDeploymentOptions, PANSSHDeployer


def test_commit_is_not_a_deployment_option_or_deploy_side_effect():
    assert "commit" not in {field.name for field in fields(PANDeploymentOptions)}
    assert "_commit_candidate" not in getsource(PANSSHDeployer.deploy)
    assert "_commit_candidate" in getsource(PANSSHDeployer.commit)
