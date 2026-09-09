"""Vendor-neutral NAT analysis output, separate from extraction accounting."""

from typing import Literal

from pydantic import BaseModel, Field


class NATInventoryItem(BaseModel):
    source_id: str
    scope: str
    object_type: str
    name: str
    nat_role: str
    subtype: str = ""
    external_mapping: str = ""
    internal_mapping: str = ""
    interface: list[str] = Field(default_factory=list)
    active_policy_refs: list[str] = Field(default_factory=list)
    disabled_policy_refs: list[str] = Field(default_factory=list)
    other_refs: list[str] = Field(default_factory=list)
    usage_state: str = "UNKNOWN"
    source_validity: str = "UNKNOWN"
    migration_compatibility: str = "REVIEW_REQUIRED"
    notes: list[str] = Field(default_factory=list)


class NATPolicySummary(BaseModel):
    source_id: str
    scope: str
    policy_id: str
    policy_name: str
    policy_status: str
    srcintf: list[str]
    dstintf: list[str]
    source: list[str]
    destination: list[str]
    services: list[str]
    nat_enabled: str
    ippool_enabled: str
    poolname: list[str]
    pool_type: list[str]
    fixedport: str
    expected_translation: str
    classification: str


class NATTrafficCoverage(BaseModel):
    scope: str
    source: list[str]
    source_ranges: list[str] = Field(default_factory=list)
    source_interfaces: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    egress: str
    egress_type: str
    matching_policy: list[str] = Field(default_factory=list)
    policy_names: list[str] = Field(default_factory=list)
    policy_order: list[int] = Field(default_factory=list)
    nat_state: Literal["COVERED", "DISABLED_ONLY", "NOT_TRANSLATED", "EXEMPT", "PARTIAL", "NO_MATCH", "UNKNOWN"]
    translation: list[str] = Field(default_factory=list)
    coverage_percent: float | None = None
    status: Literal["PASS", "WARN", "FAIL"]
    severity: str
    notes: list[str] = Field(default_factory=list)


class NATDiagnostic(BaseModel):
    diagnostic_id: str
    scope: str
    severity: str
    status: Literal["PASS", "WARN", "FAIL"]
    category: str
    objects: list[str]
    finding: str
    recommended_action: str


class NATAnalysis(BaseModel):
    schema_version: str = "1.0"
    basis: str = "Static configuration eligibility, not observed sessions or deployment validation."
    inventory: list[NATInventoryItem] = Field(default_factory=list)
    policy_summaries: list[NATPolicySummary] = Field(default_factory=list)
    traffic_coverage: list[NATTrafficCoverage] = Field(default_factory=list)
    diagnostics: list[NATDiagnostic] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
