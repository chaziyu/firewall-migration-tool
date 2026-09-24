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
        "networkaddresses": "object/networkaddresses", "hosts": "object/hosts", "networks": "object/networks", "ranges": "object/ranges",
        "networkgroups": "object/networkgroups", "protocolportobjects": "object/protocolportobjects",
        "portobjectgroups": "object/portobjectgroups", "securityzones": "object/securityzones",
        "interfacegroups": "object/interfacegroups",
        "applications": "object/applications", "timeranges": "object/timeranges",
        "realms": "object/realms", "realmusergroups": "object/realmusergroups",
        "realmusers": "object/realmusers", "localrealmusers": "object/localrealmusers",
        "slamonitors": "object/slamonitors",
        "variablesets": "object/variablesets", "urlcategories": "object/urlcategories",
    }
    _domain_policies = {
        "filepolicies": "policy/filepolicies", "decryptionpolicies": "policy/decryptionpolicies",
        "dnspolicies": "policy/dnspolicies", "intrusionpolicies": "policy/intrusionpolicies",
        "s2svpns": "policy/ftds2svpns", "ravpns": "policy/ravpns",
    }
    _domain_administration = {
        "fmc_users": "users/users", "fmc_roles": "users/authroles",
    }
    _policy_children = {
        "filepolicies": ("rules", "filepolicyrules"),
        "decryptionpolicies": ("rules", "decryptionrules"),
        "dnspolicies": ("rules", "dnsrules"),
        "intrusionpolicies": ("rule_groups", "intrusionrulegroups"),
        "s2svpns": ("endpoints", "endpoints"),
        "ravpns": ("connection_profiles", "ra-vpn-connection-profiles"),
    }

    def validate_options(self, connection):
        options = validate_connection(connection, port=443, optional=("domain",))
        verify = connection.get("verify_tls", True)
        if not isinstance(verify, bool):
            raise ValueError("verify_tls must be a boolean.")
        options["verify_tls"] = verify
        return options

    def _session(self, options):
        try:
            import requests
        except ImportError as exc:
            raise CollectionError("Live collection requires the collection extra (requests).") from exc
        session = requests.Session()
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
                    if set(item) <= {"id", "name", "type", "links", "metadata"} and re.fullmatch(r"[A-Za-z0-9_-]+", str(item.get("id", ""))):
                        detail_url = url.split("?")[0].rstrip("/") + "/" + item["id"]
                        detail = session.get(detail_url, timeout=(15, 60), allow_redirects=False)
                        detail.raise_for_status()
                        if len(detail.content) > 10_000_000 or not isinstance(detail.json(), dict):
                            raise CollectionError("FMC returned an invalid object detail.")
                        items[-1] = detail.json()
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

    def test_connection(self, options):
        session, _, _ = self._session(options)
        session.close()

    def collect(self, options):
        session = None
        try:
            session, base, domain = self._session(options)
            prefix = f'/api/fmc_config/v1/domain/{domain["id"]}'
            bundle = {"format": FMC_BUNDLE_FORMAT, "source": "fmc-rest-api", "domain": domain,
                      "objects": {}, "access_policies": [], "nat_policies": [], "devices": []}
            parts = []
            # Device ownership is collected first; device child resources stay attached to each UUID.
            self._collect_family(session, base, prefix + "/devices/devicerecords", bundle, "devices", parts)
            for device in bundle["devices"]:
                device_id = str(device.get("id", ""))
                if not re.fullmatch(r"[A-Za-z0-9_-]+", device_id):
                    parts.append(CollectionPart("device_resources/unknown", "FAILED", False))
                    continue
                device["resources"] = {}
                for key, suffix in (("static_routes", f"devices/devicerecords/{device_id}/routing/staticroutes"),
                                    ("ftd_interfaces", f"devices/devicerecords/{device_id}/ftdallinterfaces"),
                                    ("dhcp_servers", f"devices/devicerecords/{device_id}/dhcp/dhcpserver"),
                                    ("ecmp_zones", f"devices/devicerecords/{device_id}/routing/ecmpzones"),
                                    ("pbr_policies", f"devices/devicerecords/{device_id}/routing/policybasedroutes")):
                    self._collect_family(session, base, prefix + "/" + suffix, device["resources"], key, parts,
                                         f"device/{device_id}/{key}")
            for roots, target in ((self._domain_objects, bundle["objects"]),
                                  (self._domain_policies, bundle["objects"]),
                                  (self._domain_administration, bundle)):
                for name, path in roots.items():
                    self._collect_family(session, base, prefix + "/" + path, target, name, parts)
            self._collect_family(session, base, prefix + "/policy/accesspolicies", bundle, "access_policies", parts)
            self._collect_family(session, base, prefix + "/policy/ftdnatpolicies", bundle, "nat_policies", parts)
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
            for policy in bundle["nat_policies"]:
                if not re.fullmatch(r"[A-Za-z0-9_-]+", str(policy.get("id", ""))):
                    parts.append(CollectionPart("nat_rules", "FAILED", False))
                    continue
                policy["manual_rules"] = []
                self._collect_family(session, base, prefix + f'/policy/ftdnatpolicies/{policy["id"]}/manualnatrules', policy, "manual_rules", parts,
                                     f'manual_rules/{policy["id"]}')
                manual = policy.pop("manual_rules")
                policy["manual_rules_before_auto"] = [rule for rule in manual if rule.get("section") == "BEFORE_AUTO"]
                policy["manual_rules_after_auto"] = [rule for rule in manual if rule.get("section") == "AFTER_AUTO"]
                policy["manual_rules"] = [rule for rule in manual if rule.get("section") != "BEFORE_AUTO" and rule.get("section") != "AFTER_AUTO"]
                self._collect_family(session, base, prefix + f'/policy/ftdnatpolicies/{policy["id"]}/autonatrules', policy, "auto_rules", parts,
                                     f'auto_rules/{policy["id"]}')
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
