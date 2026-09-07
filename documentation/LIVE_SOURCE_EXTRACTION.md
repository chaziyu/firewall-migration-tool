# Live Source Extraction Foundation

## Scope

This phase implements source acquisition only for FortiGate. It deliberately stops before target conversion or Terraform generation.

Data flow:

```text
FortiGate SSH
    -> raw `show full-configuration` snapshot
    -> SourceSnapshot + SHA-256/completeness metadata
    -> FortiGateSourceParser.extract()
    -> ExtractionResult + canonical IRConfig
    -> IRExcelExporter
    -> source inventory workbook
```

The collector layer is under `src/fwmigrate/collectors/`. SSH/API acquisition must remain separate from vendor parsers.

## CLI

After installing the project dependencies:

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --output fortigate_source_inventory.xlsx
```

The password is prompted without echoing it.

By default the collector does not verify unknown SSH host keys. Use `--verify-host-key` when the FortiGate host key is already trusted in the local SSH known-hosts store.

## Collection behavior

The collector executes:

1. `get system status`
2. `show full-configuration`

The full configuration uses a non-PTY SSH exec channel. This avoids changing persistent FortiOS console paging settings on the source device. Collection fails closed when pager markers, CLI errors, stderr, or an empty response are detected.

The raw configuration is preserved unchanged in `SourceSnapshot.raw_config` and SHA-256 hashed before parsing. Credentials are not stored in the snapshot or workbook metadata.

## Completeness

`SourceSnapshot.complete` only means the SSH collection passed transport/content checks. Parser completeness remains governed by `ExtractionResult` and the statuses documented in `EXTRACTION_DATA_MODEL.md`.

A complete collection can therefore still contain `PARTIALLY_NORMALIZED`, `EXTRACT_ONLY`, `UNSUPPORTED`, or `PARSE_ERROR` source semantics. Those items must remain visible in the Excel extraction/audit sheets instead of being silently dropped.

## Current limitation

`src/fwmigrate/live_source_api.py` provides Flask route registration for connection testing and direct live-to-Excel extraction, but the existing monolithic `create_app()` factory has not yet registered that module. The CLI is the currently wired execution entry point. No target conversion behavior is part of this phase.
