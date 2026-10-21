from fwmigrate.web import create_app


def test_pair_discovery_lists_only_registered_workflows_with_public_metadata():
    app = create_app({"TESTING": True, "WEB_MODE": "local"})
    client = app.test_client()

    response = client.get("/api/migration/pairs")

    assert response.status_code == 200
    pairs = response.get_json()["pairs"]
    assert [item["pair_id"] for item in pairs] == [
        "fortigate_to_checkpoint",
        "fortigate_to_cisco_asa",
        "fortigate_to_juniper_srx",
        "fortigate_to_palo_alto",
        "palo_alto_to_checkpoint",
        "palo_alto_to_cisco_asa",
        "palo_alto_to_cisco_ftd",
        "palo_alto_to_fortigate",
        "palo_alto_to_juniper_srx",
    ]
    assert all("cli_application" not in item for item in pairs)
    assert all(item["export_available"] for item in pairs)
    assert all(item["destination_aware_available"] for item in pairs)
    panos_srx = next(item for item in pairs if item["pair_id"] == "palo_alto_to_juniper_srx")
    assert panos_srx["destination_aware_available"] is True
    assert panos_srx["deployment_available"] is False
    assert all(item["supported_target_versions"] for item in pairs)
    assert all(item["coverage_documentation"] for item in pairs)
    assert all(item["mapping_workflow"] and item["destination_comparison"] and item["execution_mode"]
               and item["activation_steps"] for item in pairs)
    assert "Assisted" in pairs[3]["mapping_workflow"]
    reverse = next(item for item in pairs if item["pair_id"] == "palo_alto_to_fortigate")
    assert "Automatic target proposals" in reverse["mapping_workflow"]
    assert "New target" in pairs[0]["mapping_workflow"]
    assert "without a target upload" in pairs[0]["mapping_workflow"]
    assert "Manual" in pairs[1]["mapping_workflow"]
    assert "New-device interface and zone proposals" in pairs[2]["mapping_workflow"]
    assert "engineer review" in pairs[2]["mapping_workflow"]
    assert "Hardware fit remains unverified" in pairs[2]["mapping_workflow"]
    assert all("Offline" in item["execution_mode"] for index, item in enumerate(pairs) if index != 3)
    assert pairs[0]["deployment_available"] is False
    assert pairs[0]["supported_formats"] == ["json"]
    assert pairs[1]["deployment_available"] is False
    assert pairs[2]["supported_formats"] == ["set"]
    assert pairs[3]["deployment_available"] is True
    assert pairs[4]["deployment_available"] is False

    routes = {rule.rule for rule in app.url_map.iter_rules()}
    assert any(path.startswith(pairs[0]["api_prefix"] + "/") for path in routes)
    assert any(path.startswith(pairs[2]["api_prefix"] + "/") for path in routes)
    assert any(path.startswith("/api/migration/palo_alto_to_checkpoint/") for path in routes)


def test_pair_discovery_is_stably_ordered():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()

    first = client.get("/api/migration/pairs").get_json()["pairs"]
    second = client.get("/api/migration/pairs").get_json()["pairs"]

    assert first == second
