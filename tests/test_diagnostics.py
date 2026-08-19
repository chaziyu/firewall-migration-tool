import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from fg2pan.engine.diagnostics import PaloAltoDiagnostics, DiagnosticResult


def test_diagnostics_check_terraform_found():
    diag = PaloAltoDiagnostics()
    with patch.object(diag.binary_manager, "find_binary", return_value=Path("/usr/bin/terraform")), \
         patch.object(diag.binary_manager, "get_version", return_value="1.9.5"):
        result = diag.check_terraform()
        assert result.status == "ok"
        assert "1.9.5" in result.message


def test_diagnostics_check_terraform_missing():
    diag = PaloAltoDiagnostics()
    with patch.object(diag.binary_manager, "find_binary", return_value=None):
        result = diag.check_terraform()
        assert result.status == "warning"


def test_diagnostics_check_registry_ok():
    diag = PaloAltoDiagnostics()
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.head", return_value=mock_resp):
        result = diag.check_registry()
        assert result.status == "ok"
        assert "reachable" in result.message


def test_diagnostics_check_registry_error():
    diag = PaloAltoDiagnostics()
    with patch("requests.head", side_effect=Exception("Connection refused")):
        result = diag.check_registry()
        assert result.status == "error"
        assert "Cannot reach" in result.message


def test_diagnostics_line_of_sight_ok():
    diag = PaloAltoDiagnostics()
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        result = diag.check_line_of_sight("192.168.1.1", 443)
        assert result.status == "ok"
        assert "192.168.1.1:443" in result.message


def test_diagnostics_line_of_sight_fail():
    diag = PaloAltoDiagnostics()
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 10061
        mock_sock_cls.return_value = mock_sock

        result = diag.check_line_of_sight("192.168.1.1", 443)
        assert result.status == "error"


def test_diagnostics_auth_api_key_success():
    diag = PaloAltoDiagnostics()
    xml_response = """<response status="success">
        <result>
            <system>
                <hostname>PA-5220-DC</hostname>
                <model>PA-5220</model>
                <serial>012345678901</serial>
                <sw-version>11.1.2</sw-version>
                <uptime>120 days</uptime>
            </system>
        </result>
    </response>"""

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = xml_response

    with patch("requests.get", return_value=mock_resp):
        result = diag.check_auth("192.168.1.1", api_key="test_api_key")
        assert result.status == "ok"
        assert result.details["hostname"] == "PA-5220-DC"
        assert result.details["model"] == "PA-5220"
        assert result.details["sw_version"] == "11.1.2"


def test_diagnostics_auth_user_pass_keygen_success():
    diag = PaloAltoDiagnostics()

    keygen_xml = """<response status="success">
        <result>
            <key>generated_api_key_123</key>
        </result>
    </response>"""

    sys_info_xml = """<response status="success">
        <result>
            <system>
                <hostname>PA-VM-LAB</hostname>
                <model>PA-VM</model>
                <serial>999888777</serial>
                <sw-version>11.0.0</sw-version>
            </system>
        </result>
    </response>"""

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "keygen" in url:
            resp.text = keygen_xml
        else:
            resp.text = sys_info_xml
        return resp

    with patch("requests.get", side_effect=mock_get):
        result = diag.check_auth("10.0.0.1", username="admin", password="password123")
        assert result.status == "ok"
        assert result.details["hostname"] == "PA-VM-LAB"


def test_diagnostics_run_all():
    diag = PaloAltoDiagnostics()
    with patch.object(diag, "check_terraform", return_value=DiagnosticResult(name="terraform_cli", status="ok", message="OK")), \
         patch.object(diag, "check_registry", return_value=DiagnosticResult(name="registry_access", status="ok", message="OK")), \
         patch.object(diag, "check_line_of_sight", return_value=DiagnosticResult(name="palo_alto_line_of_sight", status="ok", message="OK")), \
         patch.object(diag, "check_auth", return_value=DiagnosticResult(name="palo_alto_auth", status="ok", message="OK")):

        results = diag.run_all(host="192.168.1.1", api_key="secret")
        assert len(results) == 4
        assert all(r.status == "ok" for r in results)
