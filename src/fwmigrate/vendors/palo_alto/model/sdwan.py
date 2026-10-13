from __future__ import annotations

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANSDWANInterfaceProfile(PANNamedSourceModel):
    link_tag: str | None = None
    link_type: str | None = None
    vpn_data_tunnel_support: str | None = None
    maximum_download: str | None = None
    maximum_upload: str | None = None
    error_correction: str | None = None
    path_monitoring: str | None = None
    vpn_failover_metric: str | None = None
    probe_frequency: str | None = None
    probe_idle_time: str | None = None
    failback_hold_time: str | None = None
    comment: str | None = None


class PANSDWANPathQualityProfile(PANNamedSourceModel):
    latency_threshold: str | None = None
    latency_sensitivity: str | None = None
    packet_loss_threshold: str | None = None
    packet_loss_sensitivity: str | None = None
    jitter_threshold: str | None = None
    jitter_sensitivity: str | None = None


class PANSDWANTrafficDistributionLink(PANNestedSourceModel):
    link_tag: str | None = None
    weight: str | None = None


class PANSDWANTrafficDistributionProfile(PANNamedSourceModel):
    distribution_mode: str | None = None
    links: list[PANSDWANTrafficDistributionLink] | None = None


class PANSDWANSaaSQualityProfile(PANNamedSourceModel):
    monitor_mode: str | None = None
    probe_configuration: str | None = None
    targets: list[str] | None = None


class PANSDWANErrorCorrectionProfile(PANNamedSourceModel):
    activation_threshold: str | None = None
    mode: str | None = None


class PANSDWANRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    source_user: list[str] | None = None
    destination: list[str] | None = None
    application: list[str] | None = None
    service: list[str] | None = None
    tags: list[str] | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    path_quality_profile: str | None = None
    saas_quality_profile: str | None = None
    error_correction_profile: str | None = None
    traffic_distribution_profile: str | None = None
    nat_session_failover_action: str | None = None
    group_tag: str | None = None
    description: str | None = None
