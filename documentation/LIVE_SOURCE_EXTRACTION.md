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

## Web UI

Start the application with:

```bash
fwmigrate serve --port 5000
```

Then open the main interface:

```text
http://localhost:5000/
```

Select:

```text
Extract Data to Excel
    -> Input Method: Live Firewall
```

The integrated FortiGate live source flow provides:

1. source host, SSH port, username, password, and optional known-host verification;
2. **Test Connection**;
3. **Pull Configuration**;
4. collection completeness, hostname, FortiOS version, config size, SHA-256, commands, and warnings;
5. the existing **Download Source Inventory (.xlsx)** action after a complete pull.

`Live Firewall` is an ingestion method, not a separate migration mode. It is currently enabled only under **Extract Data to Excel** and locks the source vendor to FortiGate. **Convert Config File** and **Live Migration** continue to require an uploaded configuration file.

The old `/live-source` URL redirects to the main interface for backward compatibility. There is no separate live-source frontend to maintain.

The raw configuration is not returned to the browser. A successful pull is retained temporarily in server memory under a collection ID. Excel export uses that exact preserved snapshot and does not reconnect to the firewall. Credentials are never stored in the snapshot registry.

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

The live web input is currently FortiGate-only and uses in-memory snapshot storage. Snapshot records are intentionally non-persistent and are lost when the application restarts. Real-device validation is still required across representative FortiOS versions, models, VDOM configurations, and administrator permission profiles before claiming universal collection completeness.
