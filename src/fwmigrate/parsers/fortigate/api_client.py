import os
import re
import urllib3
import requests
from typing import Optional, Dict, Any, List, Union
from fwmigrate.parsers.fortigate.model import (
    FGConfig, FGSystemGlobal, FGInterface, FGAddress, FGAddressGroup,
    FGWildcardFQDN, FGService, FGServiceGroup, FGPolicy, FGIPPool,
    FGVIP, FGVIPGroup, FGStaticRoute, FGPhase1Interface
)

# Disable SSL warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiGateAPIClient:
    """
    REST API client for live FortiGate firewalls (/api/v2/cmdb/).
    Extracts configuration directly and instantiates native FGConfig models.
    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: int = 10
    ):
        host_clean = host.strip().rstrip('/')
        if not host_clean.startswith(('http://', 'https://')):
            self.base_url = f"https://{host_clean}:{port}"
        else:
            self.base_url = host_clean

        self.host = host_clean
        self.port = port
        self.api_key = api_key
        self.username = username
        self.password = password
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl

        # Authenticate
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}'
            })
        elif self.username and self.password:
            self._login()

    def _login(self) -> None:
        """Login using FortiGate session cookie authentication."""
        login_url = f"{self.base_url}/logincheck"
        data = {
            'username': self.username,
            'secretkey': self.password
        }
        try:
            resp = self.session.post(login_url, data=data, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to reach FortiGate at {self.base_url}: {e}")

        if resp.status_code != 200 or ('Set-Cookie' not in resp.headers and 'ccsrftoken' not in self.session.cookies):
            # Check if login returned 200 with 1 (success)
            if resp.text.strip() != "1":
                raise RuntimeError(f"FortiGate login failed for user '{self.username}' (HTTP {resp.status_code}): {resp.text}")

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Makes a GET request to a CMDB endpoint and returns results list."""
        url = f"{self.base_url}/api/v2/{endpoint}"
        query_params = params.copy() if params else {}
        query_params['vdom'] = self.vdom

        try:
            resp = self.session.get(url, params=query_params, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error connecting to FortiGate ({url}): {e}")

        if resp.status_code in (401, 403):
            raise RuntimeError(
                f"FortiGate authentication failed (HTTP {resp.status_code}) on {self.base_url}. "
                "Please verify your API token or username/password credentials and permissions."
            )

        if resp.status_code == 404:
            raise KeyError(f"Endpoint '{endpoint}' not found (HTTP 404)")

        if resp.status_code != 200:
            raise RuntimeError(f"FortiGate API request to '{endpoint}' failed (HTTP {resp.status_code}): {resp.text}")

        try:
            data = resp.json()
        except Exception:
            raise RuntimeError(f"Invalid JSON response from FortiGate '{endpoint}': {resp.text[:200]}")

        # Check FortiOS status code in response JSON if present
        if isinstance(data, dict):
            status_code = data.get('http_status') or data.get('status')
            if status_code and status_code not in (200, 'success', '200'):
                error_msg = data.get('message') or data.get('error') or str(data)
                raise RuntimeError(f"FortiGate returned error on '{endpoint}': {error_msg}")

        results = data.get('results', [])
        if isinstance(results, dict):
            return [results]
        elif isinstance(results, list):
            return results
        return []

    def validate_connection(self) -> str:
        """
        Validates connectivity and authentication against FortiGate.
        Returns the hostname on success or raises RuntimeError.
        """
        try:
            sys_global_res = self.get('cmdb/system/global')
            if sys_global_res and isinstance(sys_global_res, list) and len(sys_global_res) > 0:
                return sys_global_res[0].get('hostname', 'fortigate')
            return 'fortigate'
        except KeyError:
            # If cmdb/system/global is not accessible, fallback to verifying interface endpoint
            intf_res = self.get('cmdb/system/interface')
            return 'fortigate'
        except Exception as e:
            raise RuntimeError(f"Could not connect to FortiGate at {self.base_url}: {e}")

    def _extract_names(self, items: Union[List[Any], str, None]) -> List[str]:
        """Helper to extract list of strings from FortiGate name list / dictionary objects."""
        if not items:
            return []
        if isinstance(items, str):
            return [items]
        res = []
        for item in items:
            if isinstance(item, dict):
                val = item.get('name') or item.get('q_origin_key')
                if val:
                    res.append(str(val))
            elif isinstance(item, str):
                res.append(item)
        return res

    def extract_config(self) -> FGConfig:
        """
        Queries all primary FortiGate CMDB endpoints and constructs an FGConfig instance.
        Fails loudly if connectivity or authentication is invalid.
        """
        # Step 0: Ensure connection is valid and authenticated
        hostname = self.validate_connection()

        fg_config = FGConfig()
        fg_config.system_global = FGSystemGlobal(hostname=hostname)

        # 2. Interfaces
        try:
            intf_res = self.get('cmdb/system/interface')
            for item in intf_res:
                allowaccess = item.get('allowaccess', '')
                if isinstance(allowaccess, str):
                    allow_list = allowaccess.split()
                else:
                    allow_list = self._extract_names(allowaccess)

                ip_val = item.get('ip', '')
                if isinstance(ip_val, list):
                    ip_val = " ".join(ip_val)

                fg_config.interfaces.append(FGInterface(
                    name=item.get('name', 'unnamed'),
                    vdom=item.get('vdom', self.vdom),
                    ip=ip_val if ip_val else None,
                    allowaccess=allow_list,
                    type=item.get('type', 'physical'),
                    role=item.get('role', 'undefined'),
                    description=item.get('description') or item.get('alias'),
                    vlanid=item.get('vlanid'),
                    interface=item.get('interface')
                ))
        except (KeyError, ValueError):
            pass

        # 3. Addresses
        try:
            addr_res = self.get('cmdb/firewall/address')
            for item in addr_res:
                atype = item.get('type', 'ipmask')
                subnet_val = item.get('subnet', '')
                if isinstance(subnet_val, list):
                    subnet_val = " ".join(subnet_val)

                fg_config.addresses.append(FGAddress(
                    name=item.get('name', 'unnamed'),
                    type=atype,
                    subnet=subnet_val if subnet_val else None,
                    fqdn=item.get('fqdn'),
                    start_ip=item.get('start-ip'),
                    end_ip=item.get('end-ip'),
                    comment=item.get('comment'),
                    sdn=item.get('sdn'),
                    filter=item.get('filter')
                ))
        except (KeyError, ValueError):
            pass

        # 4. Address Groups
        try:
            addrgrp_res = self.get('cmdb/firewall/addrgrp')
            for item in addrgrp_res:
                members = self._extract_names(item.get('member', []))
                fg_config.address_groups.append(FGAddressGroup(
                    name=item.get('name', 'unnamed'),
                    member=members,
                    comment=item.get('comment')
                ))
        except (KeyError, ValueError):
            pass

        # 5. Service Objects
        try:
            svc_res = self.get('cmdb/firewall.service/custom')
            for item in svc_res:
                fg_config.services.append(FGService(
                    name=item.get('name', 'unnamed'),
                    protocol=item.get('protocol', 'TCP/UDP/SCTP'),
                    tcp_portrange=item.get('tcp-portrange'),
                    udp_portrange=item.get('udp-portrange'),
                    protocol_number=item.get('protocol-number'),
                    comment=item.get('comment')
                ))
        except (KeyError, ValueError):
            pass

        # 6. Service Groups
        try:
            svcgrp_res = self.get('cmdb/firewall.service/group')
            for item in svcgrp_res:
                members = self._extract_names(item.get('member', []))
                fg_config.service_groups.append(FGServiceGroup(
                    name=item.get('name', 'unnamed'),
                    member=members,
                    comment=item.get('comment')
                ))
        except (KeyError, ValueError):
            pass

        # 7. IP Pools (SNAT)
        try:
            pool_res = self.get('cmdb/firewall/ippool')
            for item in pool_res:
                fg_config.ip_pools.append(FGIPPool(
                    name=item.get('name', 'unnamed'),
                    type=item.get('type', 'overload'),
                    startip=item.get('startip'),
                    endip=item.get('endip'),
                    source_startip=item.get('source-startip'),
                    source_endip=item.get('source-endip'),
                    source_prefix6=item.get('source-prefix6'),
                    startport=item.get('startport'),
                    endport=item.get('endport'),
                    associated_interface=item.get('associated-interface'),
                    arp_reply=item.get('arp-reply', 'enable'),
                    arp_intf=item.get('arp-intf'),
                    permit_any_host=item.get('permit-any-host', 'disable'),
                    exclude_ip=self._extract_names(item.get('exclude-ip')),
                    block_size=item.get('block-size'),
                    num_blocks_per_user=item.get('num-blocks-per-user'),
                    pba_timeout=item.get('pba-timeout'),
                    pba_interim_log=item.get('pba-interim-log'),
                    port_per_user=item.get('port-per-user'),
                    privileged_port_use_pba=item.get('privileged-port-use-pba'),
                    nat64=item.get('nat64', 'disable'),
                    add_nat64_route=item.get('add-nat64-route'),
                    client_prefix_length=item.get('client-prefix-length'),
                    subnet_broadcast_in_ippool=item.get('subnet-broadcast-in-ippool'),
                    tcp_session_quota=item.get('tcp-session-quota'),
                    udp_session_quota=item.get('udp-session-quota'),
                    icmp_session_quota=item.get('icmp-session-quota'),
                    comments=item.get('comments')
                ))
        except (KeyError, ValueError):
            pass

        # 8. VIPs (DNAT)
        try:
            vip_res = self.get('cmdb/firewall/vip')
            for item in vip_res:
                mappedip_val = self._extract_names(item.get('mappedip'))

                known_keys = {field.replace('_', '-') for field in FGVIP.model_fields}
                extra_settings = {
                    key: (
                        '[REDACTED]'
                        if any(marker in key.lower() for marker in ('password', 'secret', 'psk', 'token', 'private-key', 'api-key'))
                        else value
                    )
                    for key, value in item.items()
                    if key not in known_keys and key not in FGVIP.model_fields
                }
                realservers = [
                    {
                        'id': server.get('id') or server.get('q_origin_key'),
                        'ip': server.get('ip'),
                        'port': server.get('port'),
                        'status': server.get('status'),
                        'weight': server.get('weight'),
                        'holddown_interval': server.get('holddown-interval'),
                    }
                    for server in item.get('realservers', [])
                    if isinstance(server, dict) and (server.get('id') or server.get('q_origin_key')) is not None
                ]

                fg_config.vips.append(FGVIP(
                    name=item.get('name', 'unnamed'),
                    id=item.get('id'),
                    uuid=item.get('uuid'),
                    type=item.get('type', 'static-nat'),
                    status=item.get('status', 'enable'),
                    extip=item.get('extip'),
                    extaddr=self._extract_names(item.get('extaddr')),
                    mappedip=mappedip_val,
                    mapped_addr=item.get('mapped-addr'),
                    extintf=item.get('extintf', 'any'),
                    arp_reply=item.get('arp-reply', 'enable'),
                    portforward=item.get('portforward', 'disable'),
                    protocol=item.get('protocol'),
                    extport=item.get('extport'),
                    mappedport=item.get('mappedport'),
                    portmapping_type=item.get('portmapping-type'),
                    nat_source_vip=item.get('nat-source-vip', 'disable'),
                    src_filter=self._extract_names(item.get('src-filter')),
                    srcintf_filter=self._extract_names(item.get('srcintf-filter')),
                    service=self._extract_names(item.get('service')),
                    gratuitous_arp_interval=item.get('gratuitous-arp-interval'),
                    ldb_method=item.get('ldb-method'),
                    server_type=item.get('server-type'),
                    persistence=item.get('persistence'),
                    http_redirect=item.get('http-redirect'),
                    monitor=self._extract_names(item.get('monitor')),
                    max_embryonic_connections=item.get('max-embryonic-connections'),
                    realservers=realservers,
                    comment=item.get('comment'),
                    color=item.get('color'),
                    extra_settings=extra_settings,
                ))
        except (KeyError, ValueError):
            pass

        # 9. Firewall Policies
        try:
            pol_res = self.get('cmdb/firewall/policy')
            for item in pol_res:
                pid = item.get('policyid') or item.get('q_origin_key', 0)
                fg_config.policies.append(FGPolicy(
                    id=int(pid),
                    name=item.get('name'),
                    srcintf=self._extract_names(item.get('srcintf', [])),
                    dstintf=self._extract_names(item.get('dstintf', [])),
                    srcaddr=self._extract_names(item.get('srcaddr', [])),
                    dstaddr=self._extract_names(item.get('dstaddr', [])),
                    action=item.get('action', 'deny'),
                    schedule=item.get('schedule', 'always'),
                    service=self._extract_names(item.get('service', [])),
                    nat=item.get('nat', 'disable'),
                    ippool=item.get('ippool', 'disable'),
                    poolname=self._extract_names(item.get('poolname', [])),
                    comments=item.get('comments'),
                    status=item.get('status', 'enable'),
                    utm_status=item.get('utm-status', 'disable')
                ))
        except (KeyError, ValueError):
            pass

        # 10. Static Routes
        try:
            route_res = self.get('cmdb/router/static')
            for item in route_res:
                rid = item.get('seq-num') or item.get('q_origin_key', 0)
                fg_config.static_routes.append(FGStaticRoute(
                    id=int(rid),
                    dst=item.get('dst'),
                    gateway=item.get('gateway'),
                    device=item.get('device'),
                    distance=int(item.get('distance', 10)),
                    comment=item.get('comment')
                ))
        except (KeyError, ValueError):
            pass

        # 11. IPsec Phase1
        try:
            p1_res = self.get('cmdb/vpn.ipsec/phase1-interface')
            for item in p1_res:
                fg_config.phase1_interfaces.append(FGPhase1Interface(
                    name=item.get('name', 'unnamed'),
                    interface=item.get('interface', 'any'),
                    ike_version=str(item.get('ike-version', '1')),
                    peertype=item.get('peertype', 'any'),
                    comments=item.get('comments'),
                    remote_gw=item.get('remote-gw'),
                    psksecret=item.get('psksecret')
                ))
        except (KeyError, ValueError):
            pass

        return fg_config
