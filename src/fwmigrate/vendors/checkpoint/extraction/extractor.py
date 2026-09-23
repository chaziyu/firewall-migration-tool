from __future__ import annotations

from ..models import CheckPointExportBundle, CollectionStatus
from ..model.source import CheckPointCollectionDiagnostic, CheckPointConfig
from .common import source_plane
from .gaia import extract_gaia_records
from .objects import extract_object_records
from .policy import extract_policy_records
from .result import ExtractionResult


def extract_checkpoint_config(bundle: CheckPointExportBundle) -> ExtractionResult:
    config = CheckPointConfig(api_version=bundle.api_version, management_server=bundle.management_server)
    for response in bundle.responses:
        complete = response.collection_status in {CollectionStatus.SUCCESS_WITH_DATA, CollectionStatus.SUCCESS_EMPTY, CollectionStatus.OK}
        config.collection.append(CheckPointCollectionDiagnostic(
            command=response.command, source_plane=source_plane(response), domain=response.domain,
            package=response.package, layer=response.layer, gateway=response.gateway,
            status=response.collection_status,
            complete=complete and (response.total is None or response.to_index == response.total),
            error=response.error, error_code=response.collection_error_code,
            from_index=response.from_index, to_index=response.to_index, total=response.total,
        ))
        if response.command.startswith("gaia/") and "cli_text" in response.data:
            records = extract_gaia_records(response)
        elif response.command in {"show-access-rulebase", "show-nat-rulebase", "show-threat-rulebase", "show-https-rulebase"}:
            bucket = "nat_rules" if response.command == "show-nat-rulebase" else "access_rules"
            records = [(bucket, item) for item in extract_policy_records(response)]
        else:
            records = extract_object_records(response)
        for bucket, item in records:
            getattr(config, bucket).append(item)
    for response in bundle.gaia_responses:
        if isinstance(response, dict):
            config.collection.append(CheckPointCollectionDiagnostic(
                command=str(response.get("command") or "gaia/show-configuration"), source_plane="gaia",
                gateway=response.get("gateway"), status=CollectionStatus(response.get("collection_status", "OK")),
                complete=not bool(response.get("error")), error=response.get("error"),
            ))
    return ExtractionResult(config=config)
