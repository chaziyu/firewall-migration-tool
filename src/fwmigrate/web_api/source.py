"""HTTP endpoints for source reporting, collection, snapshots, and Excel export."""

from __future__ import annotations

import io
import logging
from dataclasses import asdict
from time import perf_counter

from flask import jsonify, request, send_file

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
from fwmigrate.web_support.request_source import analyze_request_source
from fwmigrate.web_support.reporting import (
    ConfigurationDecodeError,
    _parse_bool,
    _safe_vendor_filename,
    _timed,
)

_LOGGER = logging.getLogger(__name__)


def register_source_routes(app) -> None:
    def live_collection_allowed() -> bool:
        if app.config.get('ALLOW_REMOTE_COLLECTION'):
            return True
        return request.remote_addr in {'127.0.0.1', '::1'}

    @app.route('/api/vendors', methods=['GET'])
    def list_vendors():
        """Return registered source-reporting vendors."""
        sources = [
            {
                'vendor_id': reporter.vendor_id,
                'display_name': getattr(reporter, 'display_name', reporter.vendor_id),
                'file_extensions': list(reporter.supported_extensions),
                'web_report': True,
                'live_collection': (
                    live_collection_allowed()
                    and reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()}
                ),
                'collection': ({'method': source_collectors.get(reporter.vendor_id).method,
                                'connection_fields': source_collectors.get(reporter.vendor_id).fields}
                               if reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()} else None),
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

            metrics = SourceReportMetrics() if _parse_bool(request.form.get('collect_metrics')) else None
            started = perf_counter()
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            entry = analyze_request_source({}, source_vendor)
            analysis = entry.analysis
            report = _timed(metrics, 'web_preview_construction', lambda: normalize_web_report(reporter.build_preview(analysis), source_vendor, copy=False))
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
        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
        except KeyError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid source configuration'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': 'Source preview failed'}), 500

    def collection_options():
        if not live_collection_allowed():
            raise PermissionError('Remote live collection is disabled on this server.')
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise ValueError('Collection request must be a JSON object.')
        collector = source_collectors.get(payload.get('vendor'))
        return collector, collector.validate_options(payload.get('connection'))

    @app.route('/api/collection/test', methods=['POST'])
    def test_collection_connection():
        try:
            collector, options = collection_options()
        except PermissionError as exc:
            _LOGGER.warning('Collection test denied by policy.', exc_info=exc)
            return jsonify({'success': False, 'error': 'Remote live collection is disabled on this server.'}), 403
        except ValueError as exc:
            _LOGGER.info('Invalid collection test request.', exc_info=exc)
            return jsonify({'success': False, 'error': 'Invalid collection request.'}), 400
        try:
            collector.test_connection(options)
            return jsonify({'success': True, 'status': 'CONNECTED'})
        except Exception:
            return jsonify({'success': False, 'error': 'Connection failed. Check the device and credentials.'}), 502

    @app.route('/api/collection/collect', methods=['POST'])
    def collect_configuration():
        try:
            collector, options = collection_options()
        except PermissionError as exc:
            _LOGGER.warning("Collection request forbidden: %s", exc)
            return jsonify({'success': False, 'error': 'Remote live collection is disabled on this server.'}), 403
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
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
        except Exception:
            return jsonify({'success': False, 'error': 'Collection or extraction failed. Check the device configuration and connection.'}), 502

    @app.route('/api/collection/snapshot/import', methods=['POST'])
    def import_collection_snapshot():
        try:
            uploaded = request.files.get('file')
            raw = uploaded.read(MAX_BYTES + 1) if uploaded else request.stream.read(MAX_BYTES + 1)
            source = parse_snapshot(raw)
            reporter = source_reporters.get(source.vendor_id)
            snapshot = make_snapshot(source)
            analysis = reporter.analyze_source(snapshot['source_text'])
            return jsonify({'success': True, 'vendor_id': source.vendor_id, 'snapshot': snapshot,
                            'collection': {'status': source.status.value, 'parts': [asdict(part) for part in source.parts],
                                           'warnings': source.warnings}, 'preview': normalize_web_report(reporter.build_preview(analysis), source.vendor_id, copy=False)})
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid or unsupported collection snapshot.'}), 400
        except Exception:
            return jsonify({'success': False, 'error': 'Snapshot import failed.'}), 400

    @app.route('/api/extract/excel', methods=['POST'])
    def extract_excel():
        """Parse a source configuration and download its vendor-native report."""
        try:
            payload = request.get_json(silent=True) or request.form.to_dict()
            source_vendor = request.form.get('source_vendor') or payload.get('source_vendor') or 'fortigate'
            metrics = (
                SourceReportMetrics()
                if _parse_bool(request.form.get('collect_metrics') or payload.get('collect_metrics'))
                or _LOGGER.isEnabledFor(logging.DEBUG)
                else None
            )
            total_started = perf_counter()
            profile_value = request.form.get('excel_profile') or payload.get('excel_profile') or ExcelExportProfile.FAST.value
            try:
                profile = ExcelExportProfile(profile_value)
            except (TypeError, ValueError):
                return jsonify({'error': 'excel_profile must be one of: fast, full'}), 400
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id

            entry = analyze_request_source(payload, source_vendor)
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
            reporter.export_excel(analysis, workbook, **export_options)
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
        except ExcelExportUnavailableError as e:
            return jsonify({'error': str(e)}), 503
        except ConfigurationDecodeError as e:
            return jsonify({'error': str(e), 'stage': 'decode'}), 400
        except KeyError as e:
            return jsonify({'error': f'Vendor-native Excel is not available: {e}'}), 422
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid source configuration'}), 400
        except Exception as e:
            return jsonify({'error': 'Source Excel export failed'}), 500

