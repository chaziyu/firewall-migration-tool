from io import BytesIO
from pathlib import Path
import zipfile

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity
from fwmigrate.web import create_app


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "all_targets_explicit.xml"


def test_review_approval_preview_download_and_bundle_share_the_approved_bytes():
    source_text = FIXTURE.read_text(encoding="utf-8")
    source_scope = next(scope for scope in build_panos_config(source_text).scopes if scope.kind == "vsys")
    source = {"vendor": "palo_alto", "source_text": source_text}
    options = {
        "source_scope": pan_scope_identity(source_scope),
        "interfaces": {"ethernet1/1": {"target_interface": "ge-0/0/0", "unit": 0},
                       "ethernet1/2": {"target_interface": "ge-0/0/1", "unit": 0}},
        "zones": {"inside": "inside", "outside": "outside"},
    }
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    prefix = "/api/migration/palo_alto_to_juniper_srx"

    prepared = client.post(prefix + "/design/prepare", json={"source": source, "options": options})
    assert prepared.status_code == 200, prepared.get_json()
    payload = prepared.get_json()
    selected = [item["key"] for item in payload["draft"]["items"]
                if item["family"] == "address" and not item["blockers"]]
    approved = client.post(prefix + "/design/approve", json={
        "source": source, "options": options, "draft": payload["draft"], "selected_items": selected,
    })
    assert approved.status_code == 200
    built = client.post(prefix + "/build", json={
        "source": source, "options": options, "approval": approved.get_json()["approval"],
    })
    assert built.status_code == 200
    artifact = built.get_json()["artifact"]
    preview = client.post(prefix + "/command-preview", json={"artifact": artifact})
    download = client.post(prefix + "/commands", json={"artifact": artifact})
    bundle = client.post(prefix + "/bundle", json={"source": source, "artifact": artifact})
    assert preview.status_code == download.status_code == bundle.status_code == 200
    command_bytes = download.data
    assert preview.get_json()["text"].encode() == command_bytes
    with zipfile.ZipFile(BytesIO(bundle.data)) as archive:
        assert archive.read("juniper_config.set") == command_bytes


def test_target_snapshot_is_bound_through_prepare_approval_and_build():
    source_text = FIXTURE.read_text(encoding="utf-8")
    source_scope = next(scope for scope in build_panos_config(source_text).scopes if scope.kind == "vsys")
    source = {"vendor": "palo_alto", "source_text": source_text}
    options = {"source_scope": pan_scope_identity(source_scope),
               "interfaces": {"ethernet1/1": {"target_interface": "ge-0/0/0", "unit": 0},
                              "ethernet1/2": {"target_interface": "ge-0/0/1", "unit": 0}},
               "zones": {"inside": "inside", "outside": "outside"}}
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    prefix = "/api/migration/palo_alto_to_juniper_srx"
    initial = client.post(prefix + "/design/prepare", json={"source": source, "options": options}).get_json()
    address = next(item for item in initial["draft"]["items"] if item["family"] == "address" and not item["blockers"])
    value = dict(address["settings"])["value"]
    target_text = f"set security address-book global address {address['target_name']} {value}\n"
    target = {"vendor": "juniper_srx", "source_text": target_text}
    metadata = {"context": "root", "version": "25.2R1", "mode": "standalone", "complete_families": ["addresses"]}
    payload = {"source": source, "options": options, "target_source": target, "target_metadata": metadata}
    prepared = client.post(prefix + "/design/prepare", json=payload)
    assert prepared.status_code == 200, prepared.get_json()
    body = prepared.get_json()
    assert body["draft"]["target_digest"]
    reused = next(item for item in body["draft"]["items"] if item["key"] == address["key"])
    assert reused["target_disposition"] == "REUSE"
    approved = client.post(prefix + "/design/approve", json={**payload, "draft": body["draft"], "selected_items": [address["key"]]})
    assert approved.status_code == 200
    artifact_response = client.post(prefix + "/build", json={**payload, "approval": approved.get_json()["approval"]})
    assert artifact_response.status_code == 200
    artifact = artifact_response.get_json()["artifact"]
    assert artifact["target_digest"] == body["draft"]["target_digest"]
    assert artifact["command_text"] == ""
    stale_target = {**target, "source_text": target_text + "set system host-name changed\n"}
    stale = client.post(prefix + "/build", json={**payload, "target_source": stale_target,
                                                  "approval": approved.get_json()["approval"]})
    assert stale.status_code == 400
