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
