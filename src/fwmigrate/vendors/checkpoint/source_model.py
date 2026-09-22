"""Check Point source-owned models built from collection envelopes."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from .models import CheckPointExportBundle, CheckPointResponse, CollectionStatus
from .resolver import infer_semantic_kind, iter_dictionary_objects


class CheckPointSourceRecord(BaseModel):
    """One source object, rule, or configuration record."""

    model_config = ConfigDict(extra="allow")

    uid: Optional[str] = None
    name: Optional[str] = None
    object_type: Optional[str] = None
    source_plane: str = "management"
    command: str
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    package: Optional[str] = None
    package_uid: Optional[str] = None
    layer: Optional[str] = None
    layer_uid: Optional[str] = None
    parent_layer_uid: Optional[str] = None
    gateway: Optional[str] = None
    order: Optional[int] = None
    members: List[Any] = Field(default_factory=list)
    references: List[Any] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CheckPointCollectionDiagnostic(BaseModel):
    command: str
    source_plane: str
    domain: Optional[str] = None
    package: Optional[str] = None
    layer: Optional[str] = None
    gateway: Optional[str] = None
    status: CollectionStatus
    complete: bool = False
    error: Optional[str] = None
    error_code: Optional[str] = None
    from_index: Optional[int] = None
    to_index: Optional[int] = None
    total: Optional[int] = None


class CheckPointConfig(BaseModel):
    """Check Point-native source aggregate; never an IR projection."""

    model_config = ConfigDict(extra="allow")

    api_version: Optional[str] = None
    management_server: Optional[str] = None
    domains: List[CheckPointSourceRecord] = Field(default_factory=list)
    packages: List[CheckPointSourceRecord] = Field(default_factory=list)
    access_layers: List[CheckPointSourceRecord] = Field(default_factory=list)
    network_objects: List[CheckPointSourceRecord] = Field(default_factory=list)
    groups: List[CheckPointSourceRecord] = Field(default_factory=list)
    services: List[CheckPointSourceRecord] = Field(default_factory=list)
    applications: List[CheckPointSourceRecord] = Field(default_factory=list)
    schedules: List[CheckPointSourceRecord] = Field(default_factory=list)
    access_rules: List[CheckPointSourceRecord] = Field(default_factory=list)
    nat_rules: List[CheckPointSourceRecord] = Field(default_factory=list)
    vpn_communities: List[CheckPointSourceRecord] = Field(default_factory=list)
    gateways: List[CheckPointSourceRecord] = Field(default_factory=list)
    identity_objects: List[CheckPointSourceRecord] = Field(default_factory=list)
    threat_prevention: List[CheckPointSourceRecord] = Field(default_factory=list)
    https_inspection: List[CheckPointSourceRecord] = Field(default_factory=list)
    gaia_interfaces: List[CheckPointSourceRecord] = Field(default_factory=list)
    gaia_routes: List[CheckPointSourceRecord] = Field(default_factory=list)
    pbr: List[CheckPointSourceRecord] = Field(default_factory=list)
    dns_ntp: List[CheckPointSourceRecord] = Field(default_factory=list)
    cluster_state: List[CheckPointSourceRecord] = Field(default_factory=list)
    management_access: List[CheckPointSourceRecord] = Field(default_factory=list)
    collection: List[CheckPointCollectionDiagnostic] = Field(default_factory=list)


def _source_plane(response: CheckPointResponse) -> str:
    return "gaia" if response.command.startswith("gaia/") else "management"


def _values(response: CheckPointResponse) -> Iterable[dict[str, Any]]:
    data = response.data
    for key in ("objects", "rulebase", "rules", "items", "interfaces", "routes"):
        value = data.get(key)
        if isinstance(value, dict):
            yield from iter_dictionary_objects(value)
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, dict))
            return


def _record(response: CheckPointResponse, value: dict[str, Any], order: int | None = None) -> CheckPointSourceRecord:
    attrs = sanitize_source_attributes(dict(value))
    refs = []
    for key in ("source", "destination", "service", "install-on", "members", "objects", "gateway", "vpn"):
        if key in value:
            refs.append(value[key])
    return CheckPointSourceRecord(
        uid=str(value["uid"]) if value.get("uid") is not None else None,
        name=str(value["name"]) if value.get("name") is not None else None,
        object_type=str(value["type"]) if value.get("type") is not None else None,
        source_plane=_source_plane(response),
        command=response.command,
        domain=response.domain,
        domain_uid=response.domain_uid,
        package=response.package,
        package_uid=response.package_uid,
        layer=response.layer,
        layer_uid=response.layer_uid,
        parent_layer_uid=response.parent_layer_uid,
        gateway=response.gateway,
        order=order,
        members=list(value.get("members") or []),
        references=refs,
        source_attributes=attrs,
    )


def _bucket(response: CheckPointResponse, value: dict[str, Any]) -> str:
    command = response.command.lower()
    if command == "show-domains":
        return "domains"
    if command == "show-packages":
        return "packages"
    if command == "show-access-layers":
        return "access_layers"
    if command == "show-access-rulebase":
        return "access_rules"
    if command == "show-nat-rulebase":
        return "nat_rules"
    if "vpn-community" in command:
        return "vpn_communities"
    if "https" in command:
        return "https_inspection"
    if "threat" in command:
        return "threat_prevention"
    if response.command.startswith("gaia/"):
        if "route" in command:
            return "gaia_routes"
        if "pbr" in command or "policy-based" in command:
            return "pbr"
        if "ntp" in command or "dns" in command:
            return "dns_ntp"
        if "cluster" in command:
            return "cluster_state"
        if "management" in command or "access" in command:
            return "management_access"
        return "gaia_interfaces"
    kind = infer_semantic_kind(value.get("type"), value.get("name"))
    if kind.value in {"ADDRESS", "SECURITY_ZONE"}:
        return "network_objects"
    if kind.value in {"ADDRESS_GROUP", "SERVICE_GROUP", "APPLICATION_GROUP", "TIME_GROUP"}:
        return "groups"
    if kind.value in {"SERVICE"}:
        return "services"
    if kind.value in {"APPLICATION", "APPLICATION_CATEGORY"}:
        return "applications"
    if kind.value in {"TIME"}:
        return "schedules"
    if "identity" in command or "user" in command or "ldap" in command or "radius" in command:
        return "identity_objects"
    if kind.value in {"INSTALL_TARGET"}:
        return "gateways"
    return "network_objects"


def build_checkpoint_config(bundle: CheckPointExportBundle) -> CheckPointConfig:
    config = CheckPointConfig(
        api_version=bundle.api_version,
        management_server=bundle.management_server,
    )
    for response in bundle.responses:
        plane = _source_plane(response)
        complete = response.collection_status in {
            CollectionStatus.SUCCESS_WITH_DATA,
            CollectionStatus.SUCCESS_EMPTY,
            CollectionStatus.OK,
        }
        config.collection.append(CheckPointCollectionDiagnostic(
            command=response.command,
            source_plane=plane,
            domain=response.domain,
            package=response.package,
            layer=response.layer,
            gateway=response.gateway,
            status=response.collection_status,
            complete=complete and (response.total is None or response.to_index == response.total),
            error=response.error,
            error_code=response.collection_error_code,
            from_index=response.from_index,
            to_index=response.to_index,
            total=response.total,
        ))
        for index, value in enumerate(_values(response), 1):
            bucket = _bucket(response, value)
            target = getattr(config, bucket)
            target.append(_record(response, value, index))
    for response in bundle.gaia_responses:
        if isinstance(response, dict):
            config.collection.append(CheckPointCollectionDiagnostic(
                command=str(response.get("command") or "gaia/show-configuration"),
                source_plane="gaia",
                gateway=response.get("gateway"),
                status=CollectionStatus(response.get("collection_status", "OK")),
                complete=not bool(response.get("error")),
                error=response.get("error"),
            ))
    return config


__all__ = ["CheckPointCollectionDiagnostic", "CheckPointConfig", "CheckPointSourceRecord", "build_checkpoint_config"]
