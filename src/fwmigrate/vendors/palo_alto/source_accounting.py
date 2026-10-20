"""Vendor-owned extraction coverage, independent of preview and Excel."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from pydantic import BaseModel

from .identity import source_identity
from .schema_registry import match_path_spec, registered_paths


_TYPED_COUNT_FIELDS = {
    "tag": "tags",
    "address": "addresses",
    "address_group": "address_groups",
    "service": "services",
    "service_group": "service_groups",
    "schedule": "schedules",
    "security_rule": "security_rules",
    "default_security_rule": "default_security_rules",
    "nat_rule": "nat_rules",
    "interface_import": "interface_imports",
    "virtual_router_import": "interface_imports",
    "interface_ethernet": "interfaces",
    "interface_aggregate-ethernet": "interfaces",
    "interface_loopback": "interfaces",
    "interface_tunnel": "interfaces",
    "interface_vlan": "interfaces",
    "zone": "zones",
    "security_profile_group": "security_profile_groups",
    "interface_unit": "interface_units",
    "management_profile": "management_profiles",
    "virtual_router": "virtual_routers",
    "logical_router": "logical_routers",
    "ipsec_tunnel": "ipsec_tunnels",
    "vulnerability_profile": "vulnerability_profiles",
    "administrator": "administrators",
    "administrator_mgt_config": "administrators",
    "admin_role": "admin_roles",
    "ike_gateway": "ike_gateways",
    "ike_crypto_profile": "ike_crypto_profiles",
    "ipsec_crypto_profile": "ipsec_crypto_profiles",
    "dhcp_server": "dhcp_servers",
    "dhcp_interface": "dhcp_servers",
    "sdwan_interface_profile": "sdwan_interface_profiles",
    "sdwan_path_quality_profile": "sdwan_path_quality_profiles",
    "sdwan_traffic_distribution_profile": "sdwan_traffic_distribution_profiles",
    "sdwan_saas_quality_profile": "sdwan_saas_quality_profiles",
    "sdwan_error_correction_profile": "sdwan_error_correction_profiles",
    "sdwan_interface_profile_cli": "sdwan_interface_profiles",
    "sdwan_path_quality_profile_cli": "sdwan_path_quality_profiles",
    "sdwan_traffic_distribution_profile_cli": "sdwan_traffic_distribution_profiles",
    "sdwan_saas_quality_profile_cli": "sdwan_saas_quality_profiles",
    "sdwan_error_correction_profile_cli": "sdwan_error_correction_profiles",
    "sdwan_rule": "sdwan_rules",
    "local_user": "local_users",
    "local_user_database": "local_users",
    "local_user_group": "local_user_groups",
    "local_user_group_compat": "local_user_groups",
    "group_mapping": "group_mappings",
    "globalprotect_portal": "globalprotect_portals",
    "globalprotect_gateway": "globalprotect_gateways",
    "globalprotect_portal_selected": "globalprotect_portals",
    "globalprotect_gateway_selected": "globalprotect_gateways",
}


@dataclass(frozen=True)
class PANDomainCoverage:
    domain: str
    source_records: int
    typed_objects: int
    status: str
    unknown_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class PANSourceAccounting:
    record_statuses: dict[tuple, str]
    coverage: tuple[PANDomainCoverage, ...]
    typed_counts: dict[str, int]
    source_domains: Counter
    extracted_domains: Counter
    domain_statuses: dict[str, tuple[str, ...]]
    typed_paths: frozenset[str]

    def inventory_status(self, record) -> str:
        return self.record_statuses[source_identity(record)[:4]]


def _has_raw_extra(value) -> bool:
    if isinstance(value, BaseModel):
        return any(bool(getattr(value, name)) if name == "raw_extra" else _has_raw_extra(getattr(value, name))
                   for name in type(value).model_fields)
    if isinstance(value, dict):
        return any(_has_raw_extra(child) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_raw_extra(child) for child in value)
    return False


def build_source_accounting(config, derived) -> PANSourceAccounting:
    typed = [item for name in set(_TYPED_COUNT_FIELDS.values()) for item in getattr(config, name)]
    typed.extend(derived.static_routes)
    by_identity = defaultdict(list)
    typed_counts = Counter()
    for item in typed:
        by_identity[source_identity(item)[:4]].append(item)
        spec = match_path_spec(tuple(item.source_path.split("/")))
        if spec:
            typed_counts[spec.name] += 1
    # Keep all registered typed domains visible, including explicit zero counts.
    for domain in _TYPED_COUNT_FIELDS:
        typed_counts.setdefault(domain, 0)
    typed_counts["static_route"] = len(derived.static_routes)
    failures = {source_identity(issue)[:4] for issue in config.extraction_issues}
    record_statuses, domain_statuses = {}, defaultdict(list)
    source_domains, extracted_domains = Counter(), Counter()
    for record in config.source_inventory:
        key = source_identity(record)[:4]
        items = by_identity.get(key, ())
        status = ("UNSUPPORTED" if record.unsupported or key in failures else
                  "PARTIAL" if items and any(_has_raw_extra(item) for item in items) else
                  "EXTRACTED" if items else "SOURCE_ONLY")
        record_statuses[key] = status
        spec = match_path_spec(tuple(record.source_path.split("/")))
        domain = spec.name if spec else record.kind.replace("-", "_")
        source_domains[domain] += 1
        domain_statuses[domain].append(status)
        if status == "EXTRACTED":
            extracted_domains[domain] += 1
    coverage = []
    for domain in sorted(set(registered_paths()) | set(source_domains) | set(typed_counts)):
        statuses = domain_statuses.get(domain, ())
        status = (statuses[0] if statuses and len(set(statuses)) == 1 else
                  "PARTIAL" if statuses else "NOT_PRESENT")
        coverage.append(PANDomainCoverage(domain, source_domains[domain], typed_counts[domain], status,
            tuple(path for path in config.unknown_paths if domain.replace("_", "-") in path)))
    return PANSourceAccounting(record_statuses, tuple(coverage), dict(typed_counts), source_domains,
                               extracted_domains, {key: tuple(value) for key, value in domain_statuses.items()},
                               frozenset(item.source_path for item in typed))
