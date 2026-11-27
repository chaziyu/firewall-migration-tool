"""HTTP endpoints for source reporting, collection, snapshots, and Excel export."""

from __future__ import annotations

import io
import logging
from dataclasses import asdict
from time import perf_counter

from flask import jsonify, request, send_file
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from fwmigrate.collection import CollectionStatus, source_collectors
from fwmigrate.collection.snapshot import MAX_BYTES, make_snapshot, parse_snapshot
from fwmigrate.source_reporting import (
    ExcelExportMetrics,
    ExcelExportProfile,
    ExcelExportUnavailableError,
    SourceReportMetrics,
    XLSX_MIMETYPE,
    source_reporters,
)
from fwmigrate.source_reporting.web_report import normalize_web_report
from fwmigrate.source_reporting.lifecycle import (
    build_fortigate_lifecycle_card,
    build_paloalto_lifecycle_card,
    evaluate_fortigate_lifecycle,
    evaluate_paloalto_lifecycle,
)
from fwmigrate.source_reporting.options import ExcelReportLimitError
from fwmigrate.vendors.fortigate.where_used import search_fortigate_where_used
from fwmigrate.vendors.palo_alto.where_used import search_paloalto_where_used
from fwmigrate.web_support.request_source import analyze_request_source
from fwmigrate.web_support.request_controls import limit_export_response, live_device_access_allowed
from fwmigrate.web_support.public_errors import safe_validation_message
from fwmigrate.web_support.reporting import (
    ConfigurationDecodeError,
    SourceSizeError,
    _parse_bool,
    _safe_vendor_filename,
    _timed,
)

_LOGGER = logging.getLogger(__name__)

_FORTIGATE_HEADER_MARKERS = (
    '#config-version=',
    'config system global',
    'config system interface',
    'config system vdom',
    'config vdom',
    'config firewall ',
    'config router ',
)


class _VendorAutoDetectError(ValueError):
    """Safe, user-facing vendor auto-detection error."""


def _detect_source_vendor(uploaded) -> str:
    """Resolve FortiGate or Palo Alto vendor from uploaded filename/header."""
    filename = (getattr(uploaded, 'filename', None) or '').strip().lower()
    if filename.endswith('.xml'):
        return 'palo_alto'
    if filename.endswith(('.conf', '.cfg')):
        return 'fortigate'
    if filename.endswith('.txt'):
        stream = getattr(uploaded, 'stream', None)
        sample = ''
        if stream is not None and hasattr(stream, 'read'):
            pos = stream.tell() if hasattr(stream, 'tell') else 0
            try:
                raw = stream.read(8192)
                if isinstance(raw, (bytes, bytearray)):
                    sample = raw.decode('utf-8', errors='replace')
                elif isinstance(raw, str):
                    sample = raw
            finally:
                if hasattr(stream, 'seek'):
                    stream.seek(pos)
        stripped = sample.lstrip().lower()
        if stripped.startswith('<?xml') or '<config' in stripped[:512]:
            return 'palo_alto'
        if any(marker in stripped for marker in _FORTIGATE_HEADER_MARKERS):
            return 'fortigate'
        return 'fortigate'
    raise _VendorAutoDetectError(
        'Could not auto-detect firewall vendor. Upload a FortiGate (.conf/.cfg/.txt) '
        'or Palo Alto PAN-OS (.xml) configuration.'
    )


def register_source_routes(app, collector_registry=None) -> None:
    def collectors():
        return collector_registry or app.config.get('SOURCE_COLLECTOR_REGISTRY') or source_collectors

    @app.errorhandler(RequestEntityTooLarge)
    def oversized_request(_error):
        return jsonify({'success': False, 'error': 'Source or snapshot exceeds the upload size limit.'}), 413

    @app.errorhandler(SourceSizeError)
    def oversized_source(_error):
        return oversized_request(_error)

    def live_collection_allowed() -> bool:
        return live_device_access_allowed(app)

    @app.route('/api/capabilities', methods=['GET'])
    def capabilities():
        return jsonify({'live_device_access': live_device_access_allowed(app)})

    @app.route('/api/vendors', methods=['GET'])
    def list_vendors():
        """Return registered source-reporting vendors."""
        active_collectors = collectors()
        registered_collectors = {collector.vendor_id: collector for collector in active_collectors.list()}
        sources = [
            {
                'vendor_id': reporter.vendor_id,
                'display_name': getattr(reporter, 'display_name', reporter.vendor_id),
                'file_extensions': list(reporter.supported_extensions),
                'max_source_bytes': MAX_BYTES,
                'max_snapshot_bytes': MAX_BYTES,
                'web_report': True,
                'live_collection': (
                    live_collection_allowed()
                    and reporter.vendor_id in registered_collectors
                ),
                'collection': ({'method': registered_collectors[reporter.vendor_id].method,
                                'connection_fields': registered_collectors[reporter.vendor_id].fields}
                               if reporter.vendor_id in registered_collectors else None),
            }
            for reporter in source_reporters.list()
        ]
        return jsonify({
            'success': True,
            'sources': sources,
        })

    @app.route('/api/preview', methods=['POST'])
    def preview_migration():
        """Read a source configuration and return a cheap, source-only preview."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            if 'file' not in request.files or request.files['file'].filename == '':
                return jsonify({'success': False, 'error': 'A configuration file is required'}), 400

            if source_vendor.strip().lower() == 'auto':
                source_vendor = _detect_source_vendor(request.files['file'])

            metrics = SourceReportMetrics() if _parse_bool(request.form.get('collect_metrics')) else None
            started = perf_counter()
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            entry = analyze_request_source({}, source_vendor, metrics=metrics)
            analysis = entry.analysis
            preview_options = {'include_source_commands': False} if source_vendor == 'fortigate' else {}
            report = _timed(metrics, 'web_preview_construction', lambda: normalize_web_report(reporter.build_preview(analysis, **preview_options), source_vendor, copy=False))
            response = {
                'success': True,
                **report,
                'source_evidence': entry.evidence, 'source_digest': entry.source_digest,
            }
            if metrics is not None:
                metrics.total_duration_ms = (perf_counter() - started) * 1000
                metrics.add('preview_total', metrics.total_duration_ms)
                response['diagnostics'] = {'metrics': metrics.as_dict()}
            return jsonify(response)
        except ConfigurationDecodeError:
            return jsonify({'success': False, 'error': 'Configuration file is not valid UTF-8.', 'stage': 'decode'}), 400
        except _VendorAutoDetectError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except KeyError:
            return jsonify({'success': False, 'error': 'Unsupported source vendor'}), 400
        except SourceSizeError:
            raise
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid source configuration'}), 400
        except HTTPException:
            raise
        except Exception:
            return jsonify({'success': False, 'error': 'Source preview failed'}), 500

    @app.route('/api/lifecycle', methods=['GET'])
    def evaluate_lifecycle():
        """Evaluate live hardware/firmware lifecycle status for FortiGate or PAN-OS."""
        vendor = (request.args.get('vendor') or '').strip().lower()
        if vendor == 'fortigate':
            model = (request.args.get('model') or '').strip()
            firmware = (request.args.get('firmware') or '').strip()
            result = evaluate_fortigate_lifecycle(model, firmware, cache_only=False)
            return jsonify({'success': True, 'lifecycle': build_fortigate_lifecycle_card(result)})
        if vendor == 'palo_alto':
            version = (request.args.get('version') or '').strip()
            exact_param = request.args.get('exact')
            is_exact = True if exact_param is None else _parse_bool(exact_param)
            result = evaluate_paloalto_lifecycle(
                version,
                is_exact_version=is_exact,
                cache_only=False,
            )
            return jsonify({'success': True, 'lifecycle': build_paloalto_lifecycle_card(result)})
        return jsonify({'success': False, 'error': 'Unsupported lifecycle vendor'}), 400

    def collection_options():
        if not live_collection_allowed():
            raise PermissionError('Remote live collection is disabled on this server.')
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise ValueError('Collection request must be a JSON object.')
        collector = collectors().get(payload.get('vendor'))
        return collector, collector.validate_options(payload.get('connection'))

    @app.route('/api/collection/test', methods=['POST'])
    def test_collection_connection():
        try:
            collector, options = collection_options()
        except PermissionError:
            _LOGGER.warning('Collection test denied by policy.')
            return jsonify({'success': False, 'error': 'Remote live collection is disabled on this server.'}), 403
        except SourceSizeError:
            raise
        except ValueError:
            _LOGGER.info('Invalid collection test request.')
            return jsonify({'success': False, 'error': 'Invalid collection request.'}), 400
        try:
            collector.test_connection(options)
            return jsonify({'success': True, 'status': 'CONNECTED'})
        except HTTPException:
            raise
        except Exception:
            return jsonify({'success': False, 'error': 'Connection failed. Check the device and credentials.'}), 502

    @app.route('/api/collection/collect', methods=['POST'])
    def collect_configuration():
        try:
            collector, options = collection_options()
        except PermissionError:
            _LOGGER.warning('Collection request denied by policy')
            return jsonify({'success': False, 'error': 'Remote live collection is disabled on this server.'}), 403
        except SourceSizeError:
            raise
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid collection request.'}), 400
        try:
            source = collector.collect(options)
            if source.status == CollectionStatus.FAILED or not source.source_text.strip():
                return jsonify({'success': False, 'error': 'Collection returned no usable source.'}), 502
            snapshot = make_snapshot(source)
            reporter = source_reporters.get(source.vendor_id)
            analysis = reporter.analyze_source(snapshot['source_text'])
            return jsonify({
                'success': True,
                'collection': {'vendor': source.vendor_id, 'method': source.method, 'status': source.status.value,
                               'parts': snapshot['parts'], 'warnings': snapshot['warnings']},
                'preview': normalize_web_report(reporter.build_preview(analysis), source.vendor_id, copy=False),
                'snapshot': snapshot,
            })
        except HTTPException:
            raise
        except Exception:
            return jsonify({'success': False, 'error': 'Collection or extraction failed. Check the device configuration and connection.'}), 502

    @app.route('/api/collection/snapshot/import', methods=['POST'])
    def import_collection_snapshot():
        try:
            uploaded = request.files.get('file')
            raw = uploaded.read(MAX_BYTES + 1) if uploaded else request.stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise SourceSizeError("Snapshot exceeds the size limit")
            source = parse_snapshot(raw)
            reporter = source_reporters.get(source.vendor_id)
            snapshot = make_snapshot(source)
            analysis = reporter.analyze_source(snapshot['source_text'])
            return jsonify({'success': True, 'vendor_id': source.vendor_id, 'snapshot': snapshot,
                            'collection': {'status': source.status.value, 'parts': [asdict(part) for part in source.parts],
                                           'warnings': source.warnings}, 'preview': normalize_web_report(reporter.build_preview(analysis), source.vendor_id, copy=False)})
        except SourceSizeError:
            raise
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid or unsupported collection snapshot.'}), 400
        except HTTPException:
            raise
        except Exception:
            return jsonify({'success': False, 'error': 'Snapshot import failed.'}), 400

    @app.route('/api/extract/excel', methods=['POST'])
    @limit_export_response
    def extract_excel():
        """Parse a source configuration and download its vendor-native report."""
        try:
            payload = request.get_json(silent=True, cache=False) if request.is_json else request.form.to_dict()
            if not isinstance(payload, dict):
                return jsonify({'error': 'Source request must be an object'}), 400
            source_vendor = request.form.get('source_vendor') or payload.get('source_vendor') or 'fortigate'
            metrics = (
                SourceReportMetrics()
                if _parse_bool(request.form.get('collect_metrics') or payload.get('collect_metrics'))
                or _LOGGER.isEnabledFor(logging.DEBUG)
                else None
            )
            total_started = perf_counter()
            default_profile = ExcelExportProfile.FULL if source_vendor == 'palo_alto' else ExcelExportProfile.FAST
            profile_value = request.form.get('excel_profile') or payload.get('excel_profile') or default_profile.value
            try:
                profile = ExcelExportProfile(profile_value)
            except (TypeError, ValueError):
                return jsonify({'error': 'excel_profile must be one of: fast, full'}), 400
            if not isinstance(source_vendor, str):
                return jsonify({'error': 'source_vendor must be a string'}), 400
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            entry = analyze_request_source(payload, source_vendor, metrics=metrics)
            analysis = entry.analysis
            workbook = io.BytesIO()
            export_started = perf_counter()
            source_name = entry.source_name
            export_metrics = (
                ExcelExportMetrics()
                if metrics is not None and profile is ExcelExportProfile.FAST and source_vendor == 'fortigate'
                else None
            )
            export_options = {'profile': profile, 'source_name': source_name}
            if entry.collection_status is not None:
                export_options['collection_status'] = entry.collection_status.value
                if isinstance(entry.evidence, dict):
                    export_options['collection_parts'] = entry.evidence.get('parts', ())
                    export_options['collection_warnings'] = entry.evidence.get('warnings', ())
            if export_metrics is not None:
                export_options['metrics'] = export_metrics
            try:
                reporter.export_excel(analysis, workbook, **export_options)
            except BaseException:
                workbook.close()
                raise
            export_elapsed = perf_counter() - export_started
            if metrics is not None:
                metrics.add('excel export call', export_elapsed * 1000)
                if export_metrics is not None:
                    metrics.details['excel_export'] = export_metrics.as_dict()
            workbook.seek(0)
            response = send_file(
                workbook,
                mimetype=XLSX_MIMETYPE,
                as_attachment=True,
                download_name=f'firewall_inventory_{_safe_vendor_filename(source_vendor)}.xlsx',
            )
            if metrics is not None:
                metrics.add('response preparation', (perf_counter() - export_started - export_elapsed) * 1000)
                metrics.total_duration_ms = (perf_counter() - total_started) * 1000
                _LOGGER.debug(
                    "Excel endpoint metrics: cache_hit=%s profile=%s %s",
                    False,
                    profile.value,
                    metrics.as_dict(),
                )
            return response
        except ExcelReportLimitError:
            return jsonify({'error': 'Report exceeds Excel worksheet limits. Reduce the source scope and retry.'}), 422
        except ExcelExportUnavailableError:
            return jsonify({'error': 'Excel export is unavailable for this source.'}), 503
        except ConfigurationDecodeError:
            return jsonify({'error': 'Configuration file is not valid UTF-8.', 'stage': 'decode'}), 400
        except KeyError:
            return jsonify({'error': 'Vendor-native Excel is not available'}), 422
        except SourceSizeError:
            raise
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid source configuration'}), 400
        except HTTPException:
            raise
        except Exception:
            return jsonify({'error': 'Source Excel export failed'}), 500

    def _run_where_used(forced_vendor: str | None = None):
        try:
            payload = request.get_json(silent=True, cache=False)
            if not isinstance(payload, dict):
                return jsonify({'success': False, 'error': 'Where-used request must be a JSON object'}), 400
            vendor = (forced_vendor or payload.get('source_vendor') or '').strip().lower()
            if vendor not in {'fortigate', 'palo_alto'}:
                return jsonify({'success': False, 'error': 'Where-used search supports fortigate and palo_alto only'}), 400
            query = payload.get('query')
            if not isinstance(query, str) or not query.strip():
                return jsonify({'success': False, 'error': 'Search query is required'}), 400
            entry = analyze_request_source(payload, vendor)
            if vendor == 'fortigate':
                result = search_fortigate_where_used(entry.analysis.extracted.config, query)
            else:
                result = search_paloalto_where_used(entry.analysis.config, query)
            return jsonify({'success': True, **result})
        except ConfigurationDecodeError:
            return jsonify({'success': False, 'error': 'Configuration file is not valid UTF-8.'}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({'success': False, 'error': safe_validation_message(exc, 'Invalid where-used request')}), 400
        except HTTPException:
            raise
        except Exception:
            return jsonify({'success': False, 'error': 'Where-used search failed'}), 500

    @app.route('/api/source/where-used', methods=['POST'])
    def source_where_used():
        """Search IPv4/CIDR/object references across FortiGate or PAN-OS source state."""
        return _run_where_used()

    @app.route('/api/fg/where-used', methods=['POST'])
    def fg_where_used():
        """Search IPv4/CIDR/object references across FortiGate source state."""
        return _run_where_used('fortigate')

    @app.route('/api/pa/where-used', methods=['POST'])
    def pa_where_used():
        """Search IPv4/CIDR/object references across PAN-OS source state."""
        return _run_where_used('palo_alto')

