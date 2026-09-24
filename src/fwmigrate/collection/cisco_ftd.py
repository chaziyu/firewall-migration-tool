"""Read-only FMC REST collection into the existing FMC export format."""

import json
import re
from dataclasses import asdict
from urllib.parse import urljoin, urlparse

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import FMC_BUNDLE_FORMAT

from .contracts import CollectedSource, CollectionError, CollectionPart, CollectionStatus, validate_connection


class CiscoFTDCollector:
    vendor_id = "cisco_ftd"
    method = "https"
    fields = (
        {"name": "host", "label": "FMC HTTPS host", "type": "text", "required": True},
        {"name": "port", "label": "HTTPS port", "type": "number", "required": True, "default": 443},
        {"name": "username", "label": "Username", "type": "text", "required": True},
        {"name": "password", "label": "Password", "type": "password", "required": True},
        {"name": "domain", "label": "Domain name or UUID", "type": "text", "required": False},
        {"name": "verify_tls", "label": "Verify TLS certificate", "type": "checkbox", "default": True},
    )
    # FMC roots are grouped by ownership so collection completeness stays diagnosable.
    _domain_objects = {
        "networkaddresses": "object/networkaddresses?expanded=true",
        "network_address_overrides": "object/networkaddressoverrides?expanded=true",
        "networkgroups": "object/networkgroups?expanded=true", "protocolportobjects": "object/protocolportobjects?expanded=true",
        "portobjectgroups": "object/portobjectgroups?expanded=true", "securityzones": "object/securityzones?expanded=true",
        "interfacegroups": "object/interfacegroups?expanded=true",
        "applications": "object/applications?expanded=true", "timeranges": "object/timeranges?expanded=true",
        "realms": "object/realms", "realmusergroups": "object/realmusergroups",
        "realmusers": "object/realmusers", "localrealmusers": "object/localrealmusers",
        "slamonitors": "object/slamonitors",
        "dhcpipv6pools": "object/dhcpipv6pools",
        "ipv4addresspools": "object/ipv4addresspools", "ipv6addresspools": "object/ipv6addresspools",
        "grouppolicies": "object/grouppolicies", "certificatemaps": "object/certificatemaps",
        "certenrollments": "object/certenrollments", "internalcertificates": "object/internalcertificates",
        "ikev1policies": "object/ikev1policies", "ikev2policies": "object/ikev2policies",
        "ikev1ipsecproposals": "object/ikev1ipsecproposals", "ikev2ipsecproposals": "object/ikev2ipsecproposals",
        "customsiurllists": "object/customsiurllists", "customsiiplists": "object/customsiiplists",
        "siurllists": "object/siurllists", "siurlfeeds": "object/siurlfeeds",
        "variablesets": "object/variablesets", "urlcategories": "object/urlcategories",
    }
    _domain_policies = {
        "filepolicies": "policy/filepolicies", "decryptionpolicies": "policy/decryptionpolicies",
        "dnspolicies": "policy/dnspolicies", "intrusionpolicies": "policy/intrusionpolicies",
        "s2svpns": "policy/ftds2svpns", "ravpns": "policy/ravpns",
        "prefilterpolicies": "policy/prefilterpolicies", "identitypolicies": "policy/identitypolicies",
        "networkanalysispolicies": "policy/networkanalysispolicies",
    }
    _domain_administration = {
        "fmc_users": "users/users", "fmc_roles": "users/authroles",
    }
    _policy_children = {
        "filepolicies": ("rules", "filerules?expanded=true"),
        "decryptionpolicies": ("rules", "decryptionpolicyrules?expanded=true"),
        "dnspolicies": ("rules", "allowdnsrules?expanded=true"),
        "intrusionpolicies": ("rule_groups", "intrusionrulegroups?expanded=true"),
        "s2svpns": ("endpoints", "endpoints"),
        "ravpns": ("connection_profiles", "connectionprofiles?expanded=true"),
        "prefilterpolicies": ("rules", "prefilterrules?expanded=true"),
        "networkanalysispolicies": ("inspectorconfigs", "inspectorconfigs?expanded=true"),
    }
    _detail_fields = {
        "networkaddresses": (("value",), ("type",)),
        "networkaddressoverrides": (("overrides",), ("value",), ("type",)),
        "policyassignments": (("policy",), ("targets",)),
        "accesspolicies": (("defaultAction",),),
        "devicerecords": (("type",),),
        "accessrules": (("action",),),
        "intrusionrules": (("ruleId", "sid"),),
        "staticroutes": (("selectedNetworks", "network", "destination"),
                         ("gateway", "gatewayAddress", "interfaceName", "interface")),
        "ipv4staticroutes": (("selectedNetworks", "network", "destination"),
                             ("gateway", "gatewayAddress", "interfaceName", "interface")),
        "ipv6staticroutes": (("selectedNetworks", "network", "destination"),
                             ("gateway", "gatewayAddress", "interfaceName", "interface")),
    }

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    def validate_options(self, connection):
        options = validate_connection(connection, port=443, optional=("domain",))
        verify = connection.get("verify_tls", True)
        if not isinstance(verify, bool):
            raise ValueError("verify_tls must be a boolean.")
        options["verify_tls"] = verify
        return options

    def _session(self, options):
        if self._session_factory is None:
            try:
                import requests
            except ImportError as exc:
                raise CollectionError("Live collection requires the collection extra (requests).") from exc
            session = requests.Session()
        else:
            session = self._session_factory()
        session.verify = options["verify_tls"]
        base = f'https://{options["host"]}:{options["port"]}'
        try:
            response = session.post(base + "/api/fmc_platform/v1/auth/generatetoken", auth=(options["username"], options["password"]), timeout=(15, 60), allow_redirects=False)
            response.raise_for_status()
            token = response.headers.get("X-auth-access-token")
            if not token:
                raise CollectionError("FMC authentication did not return an access token.")
            session.headers["X-auth-access-token"] = token
            domains = json.loads(response.headers.get("DOMAINS", "[]"))
            if not isinstance(domains, list):
                domains = []
            selected = next((item for item in domains if options["domain"] in (item.get("uuid"), item.get("name"))), None) if options["domain"] else (domains[0] if len(domains) == 1 else None)
            if selected is None:
                raise CollectionError("Select an FMC domain name or UUID.")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", str(selected.get("uuid", ""))):
                raise CollectionError("FMC returned an invalid domain identifier.")
            return session, base, {"id": selected.get("uuid"), "name": selected.get("name")}
        except Exception:
            session.close()
            raise

    def _pages(self, session, base, path):
        url = base + path
        items = []
        for _ in range(100):
            try:
                response = session.get(url, timeout=(15, 60), allow_redirects=False)
                response.raise_for_status()
                if len(response.content) > 10_000_000:
                    raise CollectionError("FMC response exceeds the size limit.")
                data = response.json()
                page = data.get("items")
                if not isinstance(page, list):
                    # Some FMC resources, including DHCP server settings, return one object.
                    if "items" not in data and isinstance(data, dict) and data:
                        return [data], True
                    raise CollectionError("FMC returned an unexpected item list.")
                for item in page:
                    if not isinstance(item, dict):
                        raise CollectionError("FMC returned an unexpected item.")
                    items.append(item)
                    if self._needs_detail(path, item):
                        parsed = urlparse(url)
                        detail_url = urljoin(base, parsed.path.rstrip("/") + "/" + item["id"] + ("?" + parsed.query if parsed.query else ""))
                        detail = session.get(detail_url, timeout=(15, 60), allow_redirects=False)
                        detail.raise_for_status()
                        detail_data = detail.json()
                        if len(detail.content) > 10_000_000 or not self._detail_is_complete(path, detail_data):
                            raise CollectionError("FMC returned an invalid object detail.")
                        items[-1] = detail_data
                paging = data.get("paging") or {}
                next_url = (paging.get("next") or {}).get("href")
                if not next_url:
                    return items, len(items) >= paging.get("total", len(items))
                parsed = urlparse(next_url)
                if (parsed.scheme and parsed.scheme != "https") or (parsed.netloc and parsed.netloc != urlparse(base).netloc):
                    raise CollectionError("FMC pagination returned an unexpected host.")
                url = urljoin(base, next_url)
            except Exception:
                return items, False
        return items, False

    @classmethod
    def _detail_fields_for(cls, path):
        endpoint = urlparse(path).path.rstrip("/").rsplit("/", 1)[-1]
        if endpoint == "accesspolicies" and "/accessrules/" not in path and "/defaultactions/" not in path:
            return cls._detail_fields["accesspolicies"]
        return next((fields for name, fields in cls._detail_fields.items()
                     if endpoint == name or endpoint.startswith(name + "/")), ())

    @classmethod
    def _needs_detail(cls, path, item):
        fields = cls._detail_fields_for(path)
        return bool(fields) and re.fullmatch(r"[A-Za-z0-9_-]+", str(item.get("id", ""))) is not None and any(
            not any(key in item for key in alternatives) for alternatives in fields)

    @classmethod
    def _detail_is_complete(cls, path, item):
        fields = cls._detail_fields_for(path)
        return isinstance(item, dict) and all(any(key in item for key in alternatives) for alternatives in fields)

    def test_connection(self, options):
        session, _, _ = self._session(options)
        session.close()

    def collect(self, options):
        session = None
        try:
            session, base, domain = self._session(options)
            prefix = f'/api/fmc_config/v1/domain/{domain["id"]}'
            bundle = {"format": FMC_BUNDLE_FORMAT, "source": "fmc-rest-api", "domain": domain,
                      "objects": {}, "access_policies": [], "nat_policies": [], "devices": [], "coverage": {}}
            parts = []
            # Device ownership is collected first; device child resources stay attached to each UUID.
            self._collect_family(session, base, prefix + "/devices/devicerecords", bundle, "devices", parts)
            for device in bundle["devices"]:
                device_id = str(device.get("id", ""))
                if not re.fullmatch(r"[A-Za-z0-9_-]+", device_id):
                    parts.append(CollectionPart("device_resources/unknown", "FAILED", False))
                    continue
                device["resources"] = {}
                for key, suffix in (("ipv4_static_routes", f"devices/devicerecords/{device_id}/routing/ipv4staticroutes?expanded=true"),
                                    ("ipv6_static_routes", f"devices/devicerecords/{device_id}/routing/ipv6staticroutes?expanded=true"),
                                    ("ftd_interfaces", f"devices/devicerecords/{device_id}/ftdallinterfaces"),
                                    ("virtual_tunnel_interfaces", f"devices/devicerecords/{device_id}/virtualtunnelinterfaces"),
                                    ("dhcp_servers", f"devices/devicerecords/{device_id}/dhcp/dhcpserver"),
                                    ("dhcp_relay_settings", f"devices/devicerecords/{device_id}/dhcp/dhcprelaysettings"),
                                    ("ecmp_zones", f"devices/devicerecords/{device_id}/routing/ecmpzones?expanded=true"),
                                    ("pbr_policies", f"devices/devicerecords/{device_id}/routing/policybasedroutes?expanded=true"),
                                    ("virtual_routers", f"devices/devicerecords/{device_id}/routing/virtualrouters?expanded=true")):
                    self._collect_family(session, base, prefix + "/" + suffix, device["resources"], key, parts,
                                         f"device/{device_id}/{key}")
                for vr in device["resources"]["virtual_routers"]:
                    vr_id = str(vr.get("id", ""))
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", vr_id):
                        parts.append(CollectionPart(f"device/{device_id}/virtual_router/unknown", "FAILED", False))
                        continue
                    vr["resources"] = {}
                    for key, endpoint in (("ipv4_static_routes", "ipv4staticroutes"), ("ipv6_static_routes", "ipv6staticroutes"),
                                          ("pbr_policies", "policybasedroutes"), ("ecmp_zones", "ecmpzones")):
                        path = prefix + f"/devices/devicerecords/{device_id}/routing/virtualrouters/{vr_id}/{endpoint}?expanded=true"
                        self._collect_family(session, base, path, vr["resources"], key, parts,
                                             f"device/{device_id}/virtual_router/{vr_id}/{key}")
            for roots, target in ((self._domain_objects, bundle["objects"]),
                                  (self._domain_policies, bundle["objects"]),
                                  (self._domain_administration, bundle)):
                for name, path in roots.items():
                    self._collect_family(session, base, prefix + "/" + path, target, name, parts)
            self._collect_family(session, base, prefix + "/devices/certificates?expanded=true", bundle["objects"],
                                 "device_certificates", parts)
            self._collect_family(session, base, prefix + "/policy/accesspolicies?expanded=true", bundle, "access_policies", parts)
            self._collect_family(session, base, prefix + "/policy/ftdnatpolicies", bundle, "nat_policies", parts)
            self._collect_family(session, base, prefix + "/assignment/policyassignments?expanded=true",
                                 bundle["objects"], "policy_assignments", parts)
            for policy in bundle["access_policies"]:
                policy_id = str(policy.get("id", ""))
                if re.fullmatch(r"[A-Za-z0-9_-]+", policy_id):
                    self._collect_family(session, base, prefix + f"/policy/accesspolicies/{policy_id}/inheritancesettings?expanded=true",
                                         policy, "inheritance_settings", parts, f"accesspolicies/{policy_id}/inheritance_settings")
                    self._collect_family(session, base, prefix + f"/policy/accesspolicies/{policy_id}/loggingsettings?expanded=true",
                                         policy, "logging_settings", parts, f"accesspolicies/{policy_id}/logging_settings")
                    self._collect_family(session, base, prefix + f"/policy/accesspolicies/{policy_id}/securityintelligencepolicies?expanded=true",
                                         policy, "security_intelligence", parts, f"accesspolicies/{policy_id}/security_intelligence")
                    self._collect_family(session, base, prefix + f"/policy/accesspolicies/{policy_id}/defaultactions?expanded=true",
                                         policy, "default_actions", parts, f"accesspolicies/{policy_id}/default_actions")
            for policy in bundle["access_policies"]:
                if not re.fullmatch(r"[A-Za-z0-9_-]+", str(policy.get("id", ""))):
                    parts.append(CollectionPart("access_rules", "FAILED", False))
                    continue
                self._collect_family(session, base, prefix + f'/policy/accesspolicies/{policy["id"]}/accessrules?expanded=true', policy, "rules", parts,
                                     f'access_rules/{policy["id"]}')
            for family, (key, endpoint) in self._policy_children.items():
                for policy in bundle["objects"].get(family, []):
                    policy_id = str(policy.get("id", ""))
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", policy_id):
                        parts.append(CollectionPart(f"{family}_children/unknown", "FAILED", False))
                        continue
                    path = f'/policy/{family}/{policy_id}/{endpoint}'
                    self._collect_family(session, base, prefix + path, policy, key, parts,
                                         f"{family}/{policy_id}/{key}")
                    if family == "intrusionpolicies":
                        self._collect_family(session, base, prefix + f"/policy/intrusionpolicies/{policy_id}/intrusionrules?expanded=true",
                                             policy, "rules", parts, f"intrusionpolicies/{policy_id}/rules")
                        self._collect_family(session, base, prefix + f"/policy/intrusionpolicies/{policy_id}/intrusionrules?expanded=true&filter=overrides:true;ipspolicy:{policy_id}",
                                             policy, "overrides", parts, f"intrusionpolicies/{policy_id}/overrides")
                    elif family == "dnspolicies":
                        self._collect_family(session, base, prefix + f"/policy/dnspolicies/{policy_id}/blockdnsrules?expanded=true",
                                             policy, "block_rules", parts, f"dnspolicies/{policy_id}/block_rules")
                    elif family == "s2svpns":
                        for key, endpoint in (("ike_settings", "ikesettings"), ("ipsec_settings", "ipsecsettings")):
                            self._collect_family(session, base, prefix + f"/policy/ftds2svpns/{policy_id}/{endpoint}?expanded=true",
                                                 policy, key, parts, f"s2svpns/{policy_id}/{key}")
                        self._collect_family(session, base, prefix + f"/policy/ftds2svpns/{policy_id}/advancedsettings?expanded=true",
                                             policy, "advanced_settings", parts, f"s2svpns/{policy_id}/advanced_settings")
                    elif family == "ravpns":
                        for key, endpoint in (("ipsec_advanced_settings", "ipsecadvancedsettings"),
                                              ("ldap_attribute_maps", "ldapattributemaps"),
                                              ("load_balance_settings", "loadbalancesettings"), ("address_assignment_settings", "addressassignmentsettings"),
                                              ("certificate_map_settings", "certificatemapsettings"),
                                              ("secure_client_customization_settings", "secureclientcustomizationsettings"),
                                              ("ipsec_crypto_maps", "ipseccryptomaps")):
                            self._collect_family(session, base, prefix + f"/policy/ravpns/{policy_id}/{endpoint}?expanded=true",
                                                 policy, key, parts, f"ravpns/{policy_id}/{key}")
                    elif family == "networkanalysispolicies":
                        self._collect_family(session, base, prefix + f"/policy/networkanalysispolicies/{policy_id}/inspectoroverrideconfigs?expanded=true",
                                             policy, "inspectoroverrideconfigs", parts,
                                             f"networkanalysispolicies/{policy_id}/inspectoroverrideconfigs")
                    elif family == "prefilterpolicies":
                        self._collect_family(session, base, prefix + f"/policy/prefilterpolicies/{policy_id}/defaultactions?expanded=true",
                                             policy, "default_actions", parts, f"prefilterpolicies/{policy_id}/default_actions")
            for policy in bundle["nat_policies"]:
                if not re.fullmatch(r"[A-Za-z0-9_-]+", str(policy.get("id", ""))):
                    parts.append(CollectionPart("nat_rules", "FAILED", False))
                    continue
                policy["manual_rules"] = []
                self._collect_family(session, base, prefix + f'/policy/ftdnatpolicies/{policy["id"]}/manualnatrules?expanded=true', policy, "manual_rules", parts,
                                     f'manual_rules/{policy["id"]}')
                manual = policy.pop("manual_rules")
                policy["manual_rules_before_auto"] = [rule for rule in manual if rule.get("section") == "BEFORE_AUTO"]
                policy["manual_rules_after_auto"] = [rule for rule in manual if rule.get("section") == "AFTER_AUTO"]
                policy["manual_rules"] = [rule for rule in manual if rule.get("section") != "BEFORE_AUTO" and rule.get("section") != "AFTER_AUTO"]
                self._collect_family(session, base, prefix + f'/policy/ftdnatpolicies/{policy["id"]}/autonatrules?expanded=true', policy, "auto_rules", parts,
                                     f'auto_rules/{policy["id"]}')
            bundle["coverage"] = {
                "address_objects": {"status": "AVAILABLE", "source": "objects/networkaddresses"},
                "network_address_overrides": {"status": "AVAILABLE", "source": "objects/networkaddressoverrides"},
                "policy_assignments": {"status": "AVAILABLE", "source": "assignment/policyassignments"},
                "address_groups": {"status": "AVAILABLE", "source": "objects/networkgroups"},
                "source_nat_ip_pools": {"status": "AVAILABLE", "source": "nat_policies and ipv4/ipv6 address pools"},
                "access_control_policy": {"status": "AVAILABLE", "source": "access_policies"},
                "inspection_profiles": {"status": "AVAILABLE", "source": "filepolicies, decryptionpolicies, dnspolicies"},
                "time_ranges": {"status": "AVAILABLE", "source": "objects/timeranges"},
                "services_groups": {"status": "AVAILABLE", "source": "protocolportobjects and portobjectgroups"},
                "destination_nat_vip": {"status": "AVAILABLE", "source": "nat_policies"},
                "vip_group_equivalent": {"status": "SOURCE_ONLY", "reason": "No synthetic VIP group is created; source objects and policy references are preserved."},
                "ips": {"status": "AVAILABLE", "source": "intrusionpolicies with configured intrusion rules"},
                "static_routes": {"status": "AVAILABLE", "source": "device global and virtual-router resources"},
                "access_profiles": {"status": "AVAILABLE", "source": "FMC auth roles"},
                "administrators": {"status": "AVAILABLE", "source": "FMC users and roles; device CLI users are a separate source plane"},
                "dhcp": {"status": "AVAILABLE", "source": "device DHCP server and relay settings"},
                "sd_wan_routing": {"status": "AVAILABLE", "source": "interfaces, virtual routers, PBR, ECMP, SLA monitors and VPN resources"},
                "security_zones": {"status": "AVAILABLE", "source": "objects/securityzones"},
                "user_groups": {"status": "AVAILABLE", "source": "realms and realmusergroups"},
                "local_users": {"status": "AVAILABLE", "source": "objects/localrealmusers"},
                "site_to_site_vpn": {"status": "AVAILABLE", "source": "s2svpns and nested resources"},
                "remote_access_vpn": {"status": "AVAILABLE", "source": "ravpns, address pools, group policies and nested resources"},
                "fmc_cli_users": {"status": "UNAVAILABLE", "reason": "No verified FMC REST endpoint exposes per-device FTD CLI users."},
            }
            # Every request remains independently represented by its CollectionPart.
            usable = any(part.count for part in parts)
            failed = any(not part.complete for part in parts)
            status = CollectionStatus.PARTIAL if failed and usable else CollectionStatus.FAILED if failed else CollectionStatus.SUCCESS
            if status == CollectionStatus.FAILED:
                raise CollectionError("FMC returned no usable configuration and some resources failed.")
            bundle["collection"] = {"status": status.value, "parts": [asdict(part) for part in parts]}
            safe = sanitize_source_attributes(bundle)
            return CollectedSource(self.vendor_id, json.dumps(safe), "live-cisco-fmc.json", self.method, status,
                                   {"domain": domain["name"]}, tuple(parts), tuple(f"{part.name}: collection incomplete" for part in parts if not part.complete))
        except CollectionError:
            raise
        except Exception as exc:
            raise CollectionError("FMC connection or collection failed.") from exc
        finally:
            if session is not None:
                session.close()

    def _collect_family(self, session, base, path, target, name, parts, part_name=None):
        items, complete = self._pages(session, base, path)
        target[name] = items
        status = "SUCCESS" if complete and items else "EMPTY" if complete else "PARTIAL" if items else "FAILED"
        parts.append(CollectionPart(part_name or name, status, complete, len(items)))
