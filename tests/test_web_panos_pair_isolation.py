import copy
from pathlib import Path
import time

from fwmigrate.web import create_app


OFFLINE_PAIRS = [
    "palo_alto_to_juniper_srx",
    "palo_alto_to_cisco_asa",
    "palo_alto_to_checkpoint",
    "palo_alto_to_cisco_ftd",
]

FIXTURE_XML = (Path(__file__).parent / "fixtures/palo_alto/all_targets_explicit.xml").read_text(encoding="utf-8")


def _payload(pair_id: str):
    base_options = {"target_mode": "new"}
    if pair_id == "palo_alto_to_cisco_ftd":
        base_options["domain_id"] = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
        base_options["policy_name"] = "PAN_ACP_test"
    elif pair_id == "palo_alto_to_checkpoint":
        base_options["policy_package"] = "Standard"
        base_options["access_layer"] = "Network"
    elif pair_id == "palo_alto_to_cisco_asa":
        base_options["mapped_interfaces"] = {
            "ethernet1/1": {"nameif": "inside", "security_level": 100},
            "ethernet1/2": {"nameif": "outside", "security_level": 0},
        }
    return {
        "source": {
            "vendor": "palo_alto",
            "source_text": FIXTURE_XML,
        },
        "options": base_options,
    }


def _prepare_and_approve(client, pair_id: str):
    data = _payload(pair_id)
    url_base = f"/api/migration/{pair_id}"
    prep = client.post(f"{url_base}/design/prepare", json=data)
    assert prep.status_code == 200, prep.get_json()
    review = prep.get_json()
    items = review["report"]["items"]
    # Pick ready items
    keys = [item["key"] for item in items if item["render_disposition"] in ("CREATE", "REUSE") and not item["blockers"]]
    assert len(keys) > 0, f"No ready items for {pair_id}"
    approve_res = client.post(
        f"{url_base}/design/approve",
        json={**data, "draft": review["draft"], "selected_items": keys},
    )
    assert approve_res.status_code == 200, approve_res.get_json()
    return data, review, approve_res.get_json()["approval"]


def test_offline_panos_pairs_have_no_live_execution_or_deployment_routes():
    app = create_app({"TESTING": True, "WEB_MODE": "local"})
    client = app.test_client()

    registered_routes = {rule.rule for rule in app.url_map.iter_rules()}

    for pair_id in OFFLINE_PAIRS:
        prefix = f"/api/migration/{pair_id}"
        # Assert no route has deploy, candidate, push, or commit
        pair_routes = [r for r in registered_routes if r.startswith(prefix)]
        assert len(pair_routes) > 0, f"No routes registered for {pair_id}"
        for route in pair_routes:
            assert "deploy" not in route.lower()
            assert "candidate" not in route.lower()
            assert "push" not in route.lower()
            assert "commit" not in route.lower()

        # Direct HTTP access to deployment endpoints returns 404
        assert client.post(f"{prefix}/deploy", json={}).status_code == 404
        assert client.post(f"{prefix}/candidate-push", json={}).status_code == 404
        assert client.post(f"{prefix}/candidate-commit", json={}).status_code == 404


def test_cross_pair_approval_replay_is_rejected():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data, _, ftd_approval = _prepare_and_approve(client, "palo_alto_to_cisco_ftd")

    # Attempt to use FTD approval on Check Point endpoint
    cp_build = client.post(
        "/api/migration/palo_alto_to_checkpoint/build",
        json={**data, "approval": ftd_approval},
    )
    assert cp_build.status_code == 400

    # Attempt to use FTD approval on ASA endpoint
    asa_build = client.post(
        "/api/migration/palo_alto_to_cisco_asa/build",
        json={**data, "approval": ftd_approval},
    )
    assert asa_build.status_code == 400


def test_source_tampering_invalidates_approval():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data, _, approval = _prepare_and_approve(client, "palo_alto_to_cisco_ftd")

    tampered_data = copy.deepcopy(data)
    tampered_data["source"]["source_text"] += "\n<!-- tampered -->"

    build_res = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/build",
        json={**tampered_data, "approval": approval},
    )
    assert build_res.status_code == 400


def test_options_tampering_invalidates_approval():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data, _, approval = _prepare_and_approve(client, "palo_alto_to_cisco_ftd")

    tampered_data = copy.deepcopy(data)
    tampered_data["options"]["policy_name"] = "TAMPERED_POLICY_NAME"

    build_res = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/build",
        json={**tampered_data, "approval": approval},
    )
    assert build_res.status_code == 400


def test_dependency_removal_in_approval_is_rejected():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data = _payload("palo_alto_to_cisco_ftd")
    url_base = "/api/migration/palo_alto_to_cisco_ftd"
    prep = client.post(f"{url_base}/design/prepare", json=data)
    assert prep.status_code == 200
    review = prep.get_json()

    # Find an item with dependencies (such as a policy rule)
    items_with_deps = [it for it in review["report"]["items"] if it.get("dependencies")]
    assert len(items_with_deps) > 0

    target_item = items_with_deps[0]
    # Request approval of ONLY the dependent item, deliberately excluding its prerequisites
    approve_res = client.post(
        f"{url_base}/design/approve",
        json={**data, "draft": review["draft"], "selected_items": [target_item["key"]]},
    )
    assert approve_res.status_code == 400
    assert "dependency" in approve_res.get_json().get("error", "").lower() or "prerequisite" in approve_res.get_json().get("error", "").lower() or approve_res.status_code == 400


def test_expired_or_nonfinite_approval_is_rejected():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data, _, approval = _prepare_and_approve(client, "palo_alto_to_cisco_ftd")

    # Expired approval
    expired_approval = copy.deepcopy(approval)
    expired_approval["expires_at"] = time.time() - 3600
    res = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/build",
        json={**data, "approval": expired_approval},
    )
    assert res.status_code == 400

    # Non-finite / invalid expires_at
    for invalid_exp in ["never", None, "invalid-timestamp"]:
        bad_approval = copy.deepcopy(approval)
        bad_approval["expires_at"] = invalid_exp
        res = client.post(
            "/api/migration/palo_alto_to_cisco_ftd/build",
            json={**data, "approval": bad_approval},
        )
        assert res.status_code == 400


def test_tampered_artifact_file_manifest_is_rejected():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data, _, approval = _prepare_and_approve(client, "palo_alto_to_cisco_ftd")

    build_res = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/build",
        json={**data, "approval": approval},
    )
    assert build_res.status_code == 200
    artifact = build_res.get_json()["artifact"]

    # 1. Content tampering without hash change
    tampered_art1 = copy.deepcopy(artifact)
    tampered_art1["files"]["cisco_fmc_operations.json"]["content"] += "tampered content"
    preview_res1 = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/artifact-preview",
        json={**data, "artifact": tampered_art1},
    )
    assert preview_res1.status_code == 400

    # 2. Deleting a required file
    tampered_art2 = copy.deepcopy(artifact)
    del tampered_art2["files"]["cisco_fmc_operations.json"]
    preview_res2 = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/artifact-preview",
        json={**data, "artifact": tampered_art2},
    )
    assert preview_res2.status_code == 400

    # 3. Bundle route also rejects tampered artifact
    bundle_res = client.post(
        "/api/migration/palo_alto_to_cisco_ftd/bundle",
        json={**data, "artifact": tampered_art1},
    )
    assert bundle_res.status_code == 400
