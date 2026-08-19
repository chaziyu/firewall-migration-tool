import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from pathlib import Path

from fwmigrate.parsers.fortigate.api_client import FortiGateAPIClient
from fwmigrate.parsers.fortigate.model import FGConfig
from fwmigrate.web import create_app
from fwmigrate.main import cli


@pytest.fixture
def client():
    app = create_app({'TESTING': True})
    return app.test_client()


def test_api_client_init_api_key():
    client = FortiGateAPIClient(
        host="192.168.1.99",
        port=8443,
        api_key="my_secret_token"
    )
    assert client.base_url == "https://192.168.1.99:8443"
    assert client.session.headers.get("Authorization") == "Bearer my_secret_token"


def test_api_client_extract_config():
    api_client = FortiGateAPIClient(host="10.0.0.1", api_key="token123")

    mock_db = {
        'cmdb/system/global': [{'hostname': 'HQ-FG-01'}],
        'cmdb/system/interface': [
            {'name': 'port1', 'ip': '192.168.1.1 255.255.255.0', 'role': 'lan', 'allowaccess': 'ping https'},
            {'name': 'port2', 'ip': '203.0.113.1 255.255.255.0', 'role': 'wan', 'allowaccess': 'ping'}
        ],
        'cmdb/firewall/address': [
            {'name': 'Web_Server', 'type': 'ipmask', 'subnet': '192.168.1.50 255.255.255.255', 'comment': 'Production Web'},
            {'name': 'DMZ_Net', 'type': 'ipmask', 'subnet': '10.0.0.0 255.255.255.0'}
        ],
        'cmdb/firewall/addrgrp': [
            {'name': 'Web_Cluster', 'member': [{'name': 'Web_Server'}], 'comment': 'Web group'}
        ],
        'cmdb/firewall.service/custom': [
            {'name': 'HTTP_Alt', 'protocol': 'TCP/UDP/SCTP', 'tcp-portrange': '8080'}
        ],
        'cmdb/firewall.service/group': [
            {'name': 'Web_Svcs', 'member': [{'name': 'HTTP_Alt'}]}
        ],
        'cmdb/firewall/ippool': [
            {'name': 'PAT_Pool', 'startip': '203.0.113.10', 'endip': '203.0.113.20'}
        ],
        'cmdb/firewall/vip': [
            {'name': 'VIP_Web', 'extip': '203.0.113.50', 'mappedip': [{'q_origin_key': '192.168.1.50'}], 'portforward': 'enable', 'extport': '80', 'mappedport': '8080'}
        ],
        'cmdb/firewall/policy': [
            {
                'policyid': 1,
                'name': 'Allow_Web_Inbound',
                'srcintf': [{'name': 'port2'}],
                'dstintf': [{'name': 'port1'}],
                'srcaddr': [{'name': 'all'}],
                'dstaddr': [{'name': 'Web_Server'}],
                'action': 'accept',
                'service': [{'name': 'HTTP_Alt'}],
                'nat': 'disable'
            }
        ],
        'cmdb/router/static': [
            {'seq-num': 1, 'dst': '0.0.0.0 0.0.0.0', 'gateway': '203.0.113.254', 'device': 'port2', 'distance': 10}
        ],
        'cmdb/vpn.ipsec/phase1-interface': [
            {'name': 'Branch_VPN', 'interface': 'port2', 'ike-version': '2', 'remote-gw': '198.51.100.1'}
        ]
    }

    def mock_get(endpoint, params=None):
        return mock_db.get(endpoint, [])

    with patch.object(api_client, "get", side_effect=mock_get):
        fg_config = api_client.extract_config()
        assert isinstance(fg_config, FGConfig)
        assert fg_config.system_global.hostname == "HQ-FG-01"
        assert len(fg_config.interfaces) == 2
        assert len(fg_config.addresses) == 2
        assert len(fg_config.address_groups) == 1
        assert len(fg_config.services) == 1
        assert len(fg_config.policies) == 1
        assert len(fg_config.static_routes) == 1
        assert len(fg_config.vips) == 1


def test_web_api_ingest_fortigate_api(client):
    fake_config = FGConfig()
    fake_config.system_global = MagicMock(hostname="Remote-FortiGate")

    with patch.object(FortiGateAPIClient, "extract_config", return_value=fake_config):
        resp = client.post('/api/ingest/fortigate-api', json={
            'host': '192.168.10.1',
            'api_key': 'valid_token'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['hostname'] == "Remote-FortiGate"
        assert 'stats' in data


def test_web_api_ingest_fortigate_api_invalid_host(client):
    resp = client.post('/api/ingest/fortigate-api', json={
        'host': 'ugjcmukykm_invalid_host_12345',
        'api_key': 'invalid_token'
    })
    assert resp.status_code == 500
    data = resp.get_json()
    assert data['success'] is False
    assert 'error' in data


def test_web_api_ingest_fortigate_api_missing_host(client):
    resp = client.post('/api/ingest/fortigate-api', json={
        'api_key': 'some_token'
    })
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert 'host is required' in data['error']


def test_web_api_ingest_fortigate_api_missing_credentials(client):
    resp = client.post('/api/ingest/fortigate-api', json={
        'host': '192.168.1.1'
    })
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert 'Please provide either' in data['error']


def test_api_client_extract_config_connection_error():
    client = FortiGateAPIClient(host="invalid_host_test_9999", api_key="dummy_token", timeout=1)
    with pytest.raises(RuntimeError) as excinfo:
        client.extract_config()
    assert "Could not connect to FortiGate" in str(excinfo.value) or "Network error" in str(excinfo.value)


def test_cli_migrate_with_fortigate_host(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "live_out"
    report_path = out_dir / "report.md"

    fake_config = FGConfig()
    fake_config.system_global = MagicMock(hostname="CLI-FG")

    with patch.object(FortiGateAPIClient, "extract_config", return_value=fake_config):
        result = runner.invoke(cli, [
            "migrate",
            "--fortigate-host", "192.168.1.1",
            "--fortigate-api-key", "token123",
            "-o", str(out_dir),
            "--format", "terraform",
            "--report", str(report_path)
        ])
        assert result.exit_code == 0
        assert (out_dir / "provider.tf").exists()
        assert (out_dir / "main.tf").exists()
