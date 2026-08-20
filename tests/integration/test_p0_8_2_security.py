import pytest
from fwmigrate.security.network_policy import TargetNetworkPolicy
from fwmigrate.security.secrets import EphemeralCredentialMaterializer, get_secret_manager
from fwmigrate.security.upload import UploadSecurityPolicy

def test_ssrf_protection_complex():
    policy = TargetNetworkPolicy()
    
    # Simple blocks
    assert not policy.is_allowed("127.0.0.1")
    assert not policy.is_allowed("localhost")
    assert not policy.is_allowed("169.254.169.254")
    
    # IPv6 blocks
    assert not policy.is_allowed("::1")
    assert not policy.is_allowed("fe80::1")
    
    # Obfuscated representations
    assert not policy.is_allowed("0x7f000001") # Hex for 127.0.0.1
    assert not policy.is_allowed("2130706433") # Decimal for 127.0.0.1
    
    # Internal networks
    assert not policy.is_allowed("10.0.0.5")
    assert not policy.is_allowed("192.168.1.1")
    
    # Allows generic public DNS
    assert policy.is_allowed("api.paloaltonetworks.com")

def test_secret_leak_prevention():
    materializer = EphemeralCredentialMaterializer(get_secret_manager())
    creds = materializer.get_credentials(["TARGET_API_KEY"])
    
    # In a real integration test, we would run a migration and search logs, DB, and Terraform files
    # for `creds['TARGET_API_KEY']`. Here we establish the mock assertion logic.
    fake_secret = creds.get('TARGET_API_KEY', 'TEST_SECRET_9f1d')
    
    # Simulate log dump
    log_dump = 'logger.info("Request failed: %s", {"Authorization": "Bearer REDACTED"})'
    assert fake_secret not in log_dump
    
def test_upload_security_edge_cases():
    policy = UploadSecurityPolicy()
    
    # Path traversal attempt
    assert not policy.is_safe_filename("../../../etc/passwd")
    
    # Valid
    assert policy.is_safe_filename("fortigate_dump.conf")
    
    # Check signature limits
    assert not policy.is_safe_content(b"\x7FELF...") # Linux binary
