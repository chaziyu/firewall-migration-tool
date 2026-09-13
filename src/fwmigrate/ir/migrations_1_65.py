from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_64_to_1_65(payload: dict[str, Any]) -> dict[str, Any]:
    """Add defaults for the additive VPN source-fidelity fields."""
    if payload.get("schema_version") != "1.64":
        return dict(payload)
    migrated = dict(payload)
    tunnel_defaults = {
        "source_auth_method": None,
        "source_remote_auth_method": None,
        "source_certificates": [],
        "source_dh_groups": [],
        "source_key_lifetime": None,
        "source_nat_traversal": None,
        "source_dpd_mode": None,
        "source_dpd_retry_count": None,
        "source_xauth_type": None,
        "source_peer_id": None,
        "source_local_id": None,
        "source_local_id_type": None,
        "source_local_gateway_ipv4": None,
        "source_local_gateway_ipv6": None,
        "source_remote_gateway_ipv4": None,
        "source_remote_gateway_ipv6": None,
        "source_remote_gateway_ddns": None,
        "source_mode_config_allow_client_selector": None,
        "source_auth_user": None,
        "source_split_exclude": [],
        "source_ipv6_split_include": [],
        "source_ipv6_split_exclude": [],
        "source_backup_gateways": [],
        "source_rekey": None,
        "source_reauth": None,
        "source_signature_hash_algorithms": [],
        "unresolved_interfaces": [],
        "unresolved_certificates": [],
        "review_reasons": [],
    }
    phase2_defaults = {
        "source_subnet6": None,
        "destination_subnet6": None,
        "source_range_start": None,
        "source_range_end": None,
        "destination_range_start": None,
        "destination_range_end": None,
        "source_range_start6": None,
        "source_range_end6": None,
        "destination_range_start6": None,
        "destination_range_end6": None,
        "source_names6": [],
        "destination_names6": [],
        "pfs": None,
        "key_lifetime": None,
        "keylife_type": None,
        "keylife_seconds": None,
        "keylife_kilobytes": None,
        "replay": None,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "review_reasons": [],
    }
    metadata = migrated.get("metadata")
    source_vendor = str(
        metadata.get("source_vendor", "") if isinstance(metadata, dict) else ""
    ).lower()
    settings = migrated.get("ssl_vpn_settings")
    if isinstance(settings, dict):
        settings.setdefault("source_addresses6", [])
    for tunnel in migrated.get("vpn_tunnels", []):
        if isinstance(tunnel, dict):
            if source_vendor in {"fortigate", "fortinet", "fortios"}:
                if tunnel.get("psk"):
                    tunnel["has_psk"] = True
                tunnel["psk"] = None
                source_attributes = tunnel.get("source_attributes")
                if isinstance(source_attributes, dict):
                    for key in tuple(source_attributes):
                        if "psk" in key.lower() or "pre_shared" in key.lower():
                            source_attributes.pop(key, None)
            for key, default in tunnel_defaults.items():
                tunnel.setdefault(key, list(default) if isinstance(default, list) else default)
    for phase2 in migrated.get("vpn_phase2", []):
        if isinstance(phase2, dict):
            for key, default in phase2_defaults.items():
                phase2.setdefault(key, list(default) if isinstance(default, list) else default)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
