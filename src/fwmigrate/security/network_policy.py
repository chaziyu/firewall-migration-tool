import ipaddress
import socket
from urllib.parse import urlparse

class NetworkPolicyViolation(Exception):
    pass

class TargetNetworkPolicy:
    """
    Validates outbound network requests to prevent SSRF and restrict connections to trusted subnets.
    """
    
    def __init__(self, allowed_cidrs: list[str] = None, allowed_ports: list[int] = None):
        self.allowed_cidrs = [ipaddress.ip_network(c) for c in (allowed_cidrs or [])]
        self.allowed_ports = allowed_ports or [443, 8443, 22]

    def is_safe_target(self, host: str, port: int) -> bool:
        """
        Validates if the target host and port are allowed.
        Rejects localhost, loopback, link-local, and IPs outside allowed CIDRs.
        """
        if port not in self.allowed_ports:
            raise NetworkPolicyViolation(f"Port {port} is not in the allowed ports list.")
            
        try:
            # Resolve hostname to IP to prevent DNS rebinding bypasses
            ip_str = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(ip_str)
        except socket.gaierror:
            raise NetworkPolicyViolation(f"Could not resolve hostname: {host}")
        except ValueError:
            raise NetworkPolicyViolation(f"Invalid IP address format for: {host}")

        # Basic anti-SSRF checks
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_private:
            raise NetworkPolicyViolation(f"Target IP {ip_str} is restricted (private/loopback/link-local/multicast).")
            
        # Enterprise allowlist check
        if self.allowed_cidrs:
            is_allowed = any(ip_obj in cidr for cidr in self.allowed_cidrs)
            if not is_allowed:
                raise NetworkPolicyViolation(f"Target IP {ip_str} is not in the allowed enterprise subnets.")
                
        return True
        
    def is_allowed(self, host: str, port: int = 443) -> bool:
        try:
            return self.is_safe_target(host, port)
        except NetworkPolicyViolation:
            return False

def validate_url(url: str, policy: TargetNetworkPolicy = TargetNetworkPolicy()):
    """Validates an entire URL against the network policy."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    if not host:
        raise NetworkPolicyViolation("Invalid URL: no hostname found.")
        
    policy.is_safe_target(host, port)
    return True
