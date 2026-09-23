from pathlib import Path

from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input


def test_management_bundle_loader_returns_bundle_and_scope():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    bundle, scope = load_checkpoint_input(source)
    assert bundle
    assert scope is not None
