import os
import re
import urllib3
import requests
from typing import Optional, Dict, Any, List, Union
from fg2pan.parser.fortigate_model import (
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
        timeout: int = 15
    ):
        host_clean = host.strip().rstrip('/')
        if not host_clean.startswith(('http://', 'https://')):
            self.base_url = f"https://{host_clean}:{port}"
        else:
            self.base_url = host_clean

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
        resp = self.session.post(login_url, data=data, timeout=self.timeout)
        if resp.status_code != 200 or 'set-cookie' not in resp.headers.get('set-cookie', '').lower() and 'ccsrftoken' not in self.session.cookies:
            # Check if login returned 200 with 1 (success)
            if resp.text.strip() != "1":
                raise RuntimeError(f"FortiGate login failed (HTTP {resp.status_code}): {resp.text}")

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Makes a GET request to a CMDB endpoint and returns results list."""
        url = f"{self.base_url}/api/v2/{endpoint}"
        query_params = params.copy() if params else {}
        query_params['vdom'] = self.vdom

        resp = self.session.get(url, params=query_params, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"FortiGate API request to '{endpoint}' failed (HTTP {resp.status_code}): {resp.text}")

        data = resp.json()
        results = data.get('results', [])
        if isinstance(results, dict):
            return [results]
        elif isinstance(results, list):
            return results
        return []

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
        """
        fg_config = FGConfig()

        # 1. System Global / Hostname
        try:
            sys_global_res = self.get('cmdb/system/global')
            if sys_global_res:
                g = sys_global_res[0]
                fg_config.system_global = FGSystemGlobal(
                    hostname=g.get('hostname', 'fortigate')
                )
        except Exception:
            fg_config.system_global = FGSystemGlobal(hostname="fortigate")

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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            pass

        # 7. IP Pools (SNAT)
        try:
            pool_res = self.get('cmdb/firewall/ippool')
            for item in pool_res:
                fg_config.ip_pools.append(FGIPPool(
                    name=item.get('name', 'unnamed'),
                    startip=item.get('startip', '0.0.0.0'),
                    endip=item.get('endip', '0.0.0.0'),
                    comments=item.get('comments')
                ))
        except Exception as e:
            pass

        # 8. VIPs (DNAT)
        try:
            vip_res = self.get('cmdb/firewall/vip')
            for item in vip_res:
                mappedip_val = item.get('mappedip', '')
                if isinstance(mappedip_val, list):
                    if mappedip_val and isinstance(mappedip_val[0], dict):
                        mappedip_val = mappedip_val[0].get('q_origin_key', '')
                    else:
                        mappedip_val = " ".join(mappedip_val)

                fg_config.vips.append(FGVIP(
                    name=item.get('name', 'unnamed'),
                    extip=item.get('extip', '0.0.0.0'),
                    mappedip=str(mappedip_val),
                    extintf=item.get('extintf', 'any'),
                    portforward=item.get('portforward', 'disable'),
                    extport=item.get('extport'),
                    mappedport=item.get('mappedport'),
                    comment=item.get('comment')
                ))
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            pass

        return fg_config
