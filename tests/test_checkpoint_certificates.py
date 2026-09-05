import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_certificate_metadata_is_extracted_without_private_material():
    result = extract_checkpoint_config(json.dumps({"responses": [{"command": "show-gateways-and-servers", "data": {"objects": [{
        "uid": "cert1", "name": "gw-cert", "type": "certificate", "subject": "CN=gw",
        "issuer": "CN=ca", "serial": "1", "fingerprint": "AA", "private-key": "secret",
    }]}}]}))
    cert = result.canonical_ir.certificates[0]
    assert cert.subject == "CN=gw"
    assert cert.sha256_fingerprint == "AA"
    assert "private-key" not in cert.source_attributes


def _extract(responses):
    return extract_checkpoint_config(json.dumps({"responses": responses}))


def test_certificate_identity_is_domain_scoped_and_references_are_not_duplicates():
    response = {"command": "show-server-certificates", "domain": "D1", "data": {"objects": [{
        "uid": "cert1", "name": "GatewayCert", "type": "certificate", "subject": "CN=gw",
        "issuer": "CN=ca", "serial": "1", "fingerprint": "AA", "valid-from": "2024-01-01T00:00:00Z",
    }]}}
    gateway = {"command": "show-gateways-and-servers", "domain": "D1", "data": {"objects": [{
        "uid": "gw1", "name": "gw", "type": "gateway", "ike-certificate": {"uid": "cert1"},
        "sic": {"status": "established", "certificate": {"uid": "cert1"}},
    }]}}
    result = _extract([response, gateway])
    assert len(result.canonical_ir.certificates) == 1
    assert {item["usage"] for item in result.canonical_ir.certificates[0].usage_references} == {"SIC", "IKE"}

    result = _extract([response, {**response, "domain": "D2", "data": {"objects": [{**response["data"]["objects"][0], "uid": "cert2"}]}}])
    assert len(result.canonical_ir.certificates) == 2


def test_certificate_safe_public_key_metadata_and_nested_secret_removal():
    result = _extract([{"command": "show-server-certificates", "domain": "D1", "data": {"objects": [{
        "uid": "cert1", "type": "certificate", "subject": "CN=gw", "public-key-algorithm": "RSA",
        "key-usage": ["digital-signature"], "public-key-size": 2048,
        "nested": {"private-key": "secret", "passphrase": "secret", "activation-key": "secret"},
    }]}}])
    cert = result.canonical_ir.certificates[0]
    assert cert.source_attributes["public-key-algorithm"] == "RSA"
    assert cert.source_attributes["public-key-size"] == 2048
    serialized = json.dumps(result.model_dump(mode="json"))
    assert '"private-key": "secret"' not in serialized
    assert '"passphrase": "secret"' not in serialized
    assert '"activation-key": "secret"' not in serialized
    assert "public-key-algorithm" in serialized


def test_sic_state_is_separate_and_unknown_state_is_preserved():
    result = _extract([{"command": "show-gateways-and-servers", "domain": "D1", "data": {"objects": [{
        "uid": "gw1", "name": "gw", "type": "gateway",
        "sic": {"status": "unknown", "certificate": {"uid": "cert1"}, "sic-password": "secret"},
    }]}}])
    sic = result.canonical_ir.checkpoint_sic_metadata[0]
    assert sic.sic_status == "unknown"
    assert sic.sic_certificate_uid == "cert1"
    assert sic.sic_credential_present is True
    assert "secret" not in json.dumps(result.model_dump(mode="json"))


def test_invalid_certificate_dates_are_preserved_as_review_evidence():
    result = _extract([{"command": "show-server-certificates", "data": {"objects": [{
        "uid": "cert1", "type": "certificate", "valid-from": "not-a-date", "valid-until": "also-bad",
    }]}}])
    cert = result.canonical_ir.certificates[0]
    assert cert.valid_from is None and cert.valid_until is None
    assert cert.review_reasons == ["invalid-certificate-valid-from", "invalid-certificate-valid-until"]
    assert cert.source_attributes["valid-from"] == "not-a-date"
