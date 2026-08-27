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
            {
                'name': 'Web_Server',
                'uuid': 'address-uuid',
                'type': 'ipmask',
                'subnet': '192.168.1.50 255.255.255.255',
                'associated-interface': 'port1',
                'allow-routing': 'enable',
                'color': 9,
                'cache-ttl': 300,
                'password': 'must-not-be-retained',
                'comment': 'Production Web',
            },
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
            {
                'name': 'PAT_Pool',
                'type': 'overload',
                'startip': '203.0.113.10',
                'endip': '203.0.113.20',
                'associated-interface': 'port2',
                'arp-reply': 'disable',
                'exclude-ip': ['203.0.113.11', '203.0.113.12'],
                'permit-any-host': 'enable',
                'block-size': 128,
                'cgn-block-size': 256,
                'cgn-client-startip': '192.168.1.10',
                'cgn-client-endip': '192.168.1.100',
                'utilization-alarm-clear': 70,
                'utilization-alarm-raise': 90,
                'api-only-pool-setting': 'retained',
            }
        ],
        'cmdb/firewall/vip': [
            {
                'name': 'VIP_Web',
                'extip': '203.0.113.50',
                'mappedip': [
                    {'q_origin_key': '192.168.1.50'},
                    {'q_origin_key': '192.168.1.51'},
                ],
                'portforward': 'enable',
                'protocol': 'udp',
                'extport': '80',
                'mappedport': '8080',
                'realservers': [
                    {
                        'q_origin_key': 1,
                        'ip': '192.168.1.50',
                        'type': 'address',
                        'address': 'DYNAMIC_BACKEND',
                        'port': 8080,
                        'holddown-interval': 30,
                        'healthcheck': 'enable',
                        'http-host': 'backend.example.com',
                        'translate-host': 'internal.example.com',
                        'max-connections': 500,
                        'monitor': ['HTTPS_MON'],
                        'client-ip': '192.168.1.0/24',
                        'api-only-server-setting': 'retained',
                    }
                ],
            }
        ],
        'cmdb/firewall/vipgrp': [
            {
                'name': 'Published_VIPs',
                'uuid': 'vipgrp-uuid',
                'interface': 'port2',
                'member': [{'name': 'VIP_Web'}],
                'color': 6,
                'comments': 'Published services',
                'api-only-group-setting': 'retained',
            }
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
        ],
        'cmdb/system/admin': [{
            'name': 'guest-admin', 'accprofile': 'auditor',
            'vdom': [{'name': 'root'}, {'name': 'customer-a'}],
            'guest-usergroups': [{'name': 'Guest Group A'}, {'name': 'Guest Group B'}],
            'trusthost3': '192.0.2.3 255.255.255.255',
            'ip6-trusthost5': '2001:db8::5/128', 'passwd': 'must-not-appear',
        }],
        'cmdb/system/accprofile': [{
            'name': 'auditor',
            'fwgrp-permission': {'policy': 'read', 'address': 'read-write'},
        }],
    }

    def mock_get(endpoint, params=None):
        return mock_db.get(endpoint, [])

    with patch.object(api_client, "get", side_effect=mock_get):
        fg_config = api_client.extract_config()
        assert isinstance(fg_config, FGConfig)
        assert fg_config.system_global.hostname == "HQ-FG-01"
        assert len(fg_config.interfaces) == 2
        assert len(fg_config.addresses) == 2
        assert fg_config.addresses[0].uuid == 'address-uuid'
        assert fg_config.addresses[0].associated_interface == 'port1'
        assert fg_config.addresses[0].allow_routing == 'enable'
        assert fg_config.addresses[0].color == 9
        assert fg_config.addresses[0].extra_settings == {
            'cache_ttl': 300,
            'password': '[REDACTED]',
        }
        assert fg_config.administrators[0].guest_usergroups == ['Guest Group A', 'Guest Group B']
        assert fg_config.administrators[0].trusthost3 == '192.0.2.3 255.255.255.255'
        assert fg_config.administrators[0].ip6_trusthost5 == '2001:db8::5/128'
        assert fg_config.administrators[0].credential_configured is True
        assert 'must-not-appear' not in fg_config.model_dump_json()
        assert fg_config.admin_profiles[0].permission_blocks[0].settings['policy'] == 'read'
        assert len(fg_config.address_groups) == 1
        assert len(fg_config.services) == 1
        assert len(fg_config.ip_pools) == 1
        assert fg_config.ip_pools[0].associated_interface == 'port2'
        assert fg_config.ip_pools[0].arp_reply == 'disable'
        assert fg_config.ip_pools[0].exclude_ip == ['203.0.113.11', '203.0.113.12']
        assert fg_config.ip_pools[0].permit_any_host == 'enable'
        assert fg_config.ip_pools[0].cgn_block_size == 256
        assert fg_config.ip_pools[0].cgn_client_startip == '192.168.1.10'
        assert fg_config.ip_pools[0].utilization_alarm_raise == 90
        assert fg_config.ip_pools[0].extra_settings == {
            'api_only_pool_setting': 'retained',
        }
        assert len(fg_config.policies) == 1
        assert len(fg_config.static_routes) == 1
        assert len(fg_config.vips) == 1
        assert fg_config.vips[0].mappedip == ['192.168.1.50', '192.168.1.51']
        assert fg_config.vips[0].protocol == 'udp'
        assert fg_config.vips[0].realservers[0].id == 1
        assert fg_config.vips[0].realservers[0].holddown_interval == 30
        server = fg_config.vips[0].realservers[0]
        assert server.type == 'address'
        assert server.address == 'DYNAMIC_BACKEND'
        assert server.healthcheck == 'enable'
        assert server.http_host == 'backend.example.com'
        assert server.translate_host == 'internal.example.com'
        assert server.max_connections == 500
        assert server.monitor == ['HTTPS_MON']
        assert server.client_ip == '192.168.1.0/24'
        assert server.extra_settings == {'api_only_server_setting': 'retained'}
        assert len(fg_config.vip_groups) == 1
        assert fg_config.vip_groups[0].member == ['VIP_Web']
        assert fg_config.vip_groups[0].comments == 'Published services'
        assert fg_config.vip_groups[0].extra_settings == {
            'api_only_group_setting': 'retained',
        }


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
