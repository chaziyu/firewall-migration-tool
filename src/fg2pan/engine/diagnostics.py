import socket
import ssl
import json
import urllib3
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, Field

from fg2pan.engine.binary_manager import TerraformBinaryManager

# Suppress InsecureRequestWarning when users connect to devices with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DiagnosticResult(BaseModel):
    name: str
    status: Literal["ok", "warning", "error", "skipped"]
    message: str
    details: Optional[Dict[str, Any]] = None


class PaloAltoDiagnostics:
    """
    Pre-flight network, registry, binary, and credentials diagnostic engine.
    """

    def __init__(self, binary_manager: Optional[TerraformBinaryManager] = None):
        self.binary_manager = binary_manager or TerraformBinaryManager()

    def check_terraform(self, auto_download: bool = False) -> DiagnosticResult:
        """Verify Terraform CLI availability and version."""
        try:
            if auto_download:
                bin_path = self.binary_manager.get_or_download()
            else:
                bin_path = self.binary_manager.find_binary()

            if not bin_path:
                return DiagnosticResult(
                    name="terraform_cli",
                    status="warning",
                    message="Terraform CLI is not installed in PATH or bin/. Auto-download will be triggered on first run.",
                    details={"installed": False}
                )

            version = self.binary_manager.get_version(bin_path)
            return DiagnosticResult(
                name="terraform_cli",
                status="ok",
                message=f"Terraform CLI is ready (v{version or 'unknown'})",
                details={
                    "installed": True,
                    "version": version,
                    "path": str(bin_path)
                }
            )
        except Exception as e:
            return DiagnosticResult(
                name="terraform_cli",
                status="error",
                message=f"Error checking Terraform CLI: {e}",
                details={"error": str(e)}
            )

    def check_registry(self, timeout: float = 5.0) -> DiagnosticResult:
        """Verify HTTPS connectivity to Terraform Provider Registry."""
        url = "https://registry.terraform.io"
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            if resp.status_code < 400:
                return DiagnosticResult(
                    name="registry_access",
                    status="ok",
                    message="Terraform registry (registry.terraform.io) is reachable",
                    details={"status_code": resp.status_code, "url": url}
                )
            else:
                return DiagnosticResult(
                    name="registry_access",
                    status="warning",
                    message=f"Terraform registry responded with HTTP {resp.status_code}",
                    details={"status_code": resp.status_code, "url": url}
                )
        except Exception as e:
            return DiagnosticResult(
                name="registry_access",
                status="error",
                message=f"Cannot reach Terraform registry ({url}): {e}",
                details={"error": str(e), "url": url}
            )

    def check_line_of_sight(
        self,
        host: str,
        port: int = 443,
        timeout: float = 3.0
    ) -> DiagnosticResult:
        """Perform a TCP socket probe to verify connectivity to target Palo Alto firewall."""
        if not host:
            return DiagnosticResult(
                name="palo_alto_line_of_sight",
                status="skipped",
                message="No target firewall hostname or IP provided"
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, int(port)))
            if result == 0:
                return DiagnosticResult(
                    name="palo_alto_line_of_sight",
                    status="ok",
                    message=f"TCP connection established to {host}:{port}",
                    details={"host": host, "port": port}
                )
            else:
                return DiagnosticResult(
                    name="palo_alto_line_of_sight",
                    status="error",
                    message=f"Failed to connect to {host}:{port} (socket error code {result})",
                    details={"host": host, "port": port, "error_code": result}
                )
        except socket.gaierror as e:
            return DiagnosticResult(
                name="palo_alto_line_of_sight",
                status="error",
                message=f"DNS resolution failed for hostname '{host}': {e}",
                details={"host": host, "port": port, "error": str(e)}
            )
        except socket.timeout:
            return DiagnosticResult(
                name="palo_alto_line_of_sight",
                status="error",
                message=f"Connection timed out after {timeout}s trying to reach {host}:{port}",
                details={"host": host, "port": port}
            )
        except Exception as e:
            return DiagnosticResult(
                name="palo_alto_line_of_sight",
                status="error",
                message=f"Network error connecting to {host}:{port}: {e}",
                details={"host": host, "port": port, "error": str(e)}
            )
        finally:
            sock.close()

    def check_auth(
        self,
        host: str,
        port: int = 443,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 5.0
    ) -> DiagnosticResult:
        """
        Authenticate against the Palo Alto XML API and query system information.
        """
        if not host:
            return DiagnosticResult(
                name="palo_alto_auth",
                status="skipped",
                message="No target firewall hostname or IP provided"
            )

        if not api_key and not (username and password):
            return DiagnosticResult(
                name="palo_alto_auth",
                status="skipped",
                message="No authentication credentials provided (requires API key or username/password)"
            )

        base_url = f"https://{host}:{port}/api"
        effective_key = api_key

        try:
            # 1. If username/password provided without API key, request API key
            if not effective_key and username and password:
                keygen_url = f"{base_url}/?type=keygen&user={username}&password={password}"
                keygen_resp = requests.get(keygen_url, verify=verify_ssl, timeout=timeout)
                if keygen_resp.status_code != 200:
                    return DiagnosticResult(
                        name="palo_alto_auth",
                        status="error",
                        message=f"Failed keygen authentication: HTTP {keygen_resp.status_code}",
                        details={"status_code": keygen_resp.status_code}
                    )
                root = ET.fromstring(keygen_resp.text)
                if root.get("status") != "success":
                    msg = root.findtext(".//msg") or "Invalid credentials"
                    return DiagnosticResult(
                        name="palo_alto_auth",
                        status="error",
                        message=f"Authentication failed: {msg}",
                        details={"response": keygen_resp.text}
                    )
                key_elem = root.find(".//key")
                if key_elem is not None and key_elem.text:
                    effective_key = key_elem.text

            # 2. Query System Information
            info_url = f"{base_url}/?type=op&cmd=<show><system><info></info></system></show>&key={effective_key}"
            info_resp = requests.get(info_url, verify=verify_ssl, timeout=timeout)

            if info_resp.status_code != 200:
                return DiagnosticResult(
                    name="palo_alto_auth",
                    status="error",
                    message=f"Palo Alto API query failed: HTTP {info_resp.status_code}",
                    details={"status_code": info_resp.status_code}
                )

            root = ET.fromstring(info_resp.text)
            if root.get("status") != "success":
                msg = root.findtext(".//msg") or "API request rejected"
                return DiagnosticResult(
                    name="palo_alto_auth",
                    status="error",
                    message=f"PAN-OS API error: {msg}",
                    details={"response": info_resp.text}
                )

            # Extract hardware & version details
            result_elem = root.find(".//result/system")
            details = {}
            if result_elem is not None:
                details["hostname"] = result_elem.findtext("hostname")
                details["model"] = result_elem.findtext("model")
                details["serial"] = result_elem.findtext("serial")
                details["sw_version"] = result_elem.findtext("sw-version")
                details["uptime"] = result_elem.findtext("uptime")

            model = details.get("model", "PAN-OS Device")
            version = details.get("sw_version", "unknown")
            hostname = details.get("hostname", host)

            return DiagnosticResult(
                name="palo_alto_auth",
                status="ok",
                message=f"Authenticated to {hostname} ({model}, PAN-OS {version})",
                details=details
            )

        except ET.ParseError as e:
            return DiagnosticResult(
                name="palo_alto_auth",
                status="error",
                message=f"Invalid XML response from firewall: {e}",
                details={"error": str(e)}
            )
        except requests.exceptions.SSLError as e:
            return DiagnosticResult(
                name="palo_alto_auth",
                status="error",
                message=f"SSL/TLS Certificate verification failed: {e}. Enable 'Insecure SSL' if using self-signed certificates.",
                details={"error": str(e)}
            )
        except Exception as e:
            return DiagnosticResult(
                name="palo_alto_auth",
                status="error",
                message=f"Authentication check failed: {e}",
                details={"error": str(e)}
            )

    def run_all(
        self,
        host: Optional[str] = None,
        port: int = 443,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        auto_download_tf: bool = False
    ) -> List[DiagnosticResult]:
        """Run the complete diagnostics suite."""
        results = []

        # 1. Check Terraform binary
        results.append(self.check_terraform(auto_download=auto_download_tf))

        # 2. Check Terraform Registry
        results.append(self.check_registry())

        # 3. Check Firewall Line of Sight
        if host:
            results.append(self.check_line_of_sight(host, port=port))
        else:
            results.append(DiagnosticResult(
                name="palo_alto_line_of_sight",
                status="skipped",
                message="No host provided"
            ))

        # 4. Check Authentication
        if host and (api_key or (username and password)):
            results.append(self.check_auth(
                host=host,
                port=port,
                api_key=api_key,
                username=username,
                password=password,
                verify_ssl=verify_ssl
            ))
        else:
            results.append(DiagnosticResult(
                name="palo_alto_auth",
                status="skipped",
                message="Credentials or host not specified"
            ))

        return results
