"""HTTP endpoints for source reporting, collection, snapshots, and Excel export."""

from __future__ import annotations

import io
import logging
import os
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
from fwmigrate.web_support.preview_cache import (
    _cache_preview,
    _clone_preview,
    _lookup_preview,
    _lookup_source_preview,
)
from fwmigrate.web_support.reporting import (
    ConfigurationDecodeError,
    _decode_configuration,
    _extract_source_config,
    _parse_bool,
    _safe_vendor_filename,
    _timed,
)

_LOGGER = logging.getLogger(__name__)


def _conversion_unavailable():
    return jsonify({
        "error": (
            "Migration planning is temporarily unavailable while the "
            "pair-specific planning architecture is being implemented."
        ),
    }), 503


def register_source_routes(app) -> None:
    @app.route('/api/vendors', methods=['GET'])
    def list_vendors():
        """Return registered source-reporting vendors."""
        sources = [
            {
                'vendor_id': reporter.vendor_id,
                'display_name': getattr(reporter, 'display_name', reporter.vendor_id),
                'file_extensions': list(reporter.supported_extensions),
                'web_report': True,
                'live_collection': reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()},
                'collection': ({'method': source_collectors.get(reporter.vendor_id).method,
                                'connection_fields': source_collectors.get(reporter.vendor_id).fields}
                               if reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()} else None),
            }
            for reporter in source_reporters.list()
        ]
        return jsonify({
            'success': True,
            'sources': sources,
            'targets': [],
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
            file = request.files['file']
            raw_content = file.read()
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            preview_entry = _timed(
                metrics, 'analysis cache lookup',
                lambda: _lookup_source_preview(source_vendor, raw_content),
            )
            analysis_cache_hit = preview_entry is not None
            if preview_entry is None:
                file_content = _timed(metrics, 'decode', lambda: _decode_configuration(raw_content))
                analysis = _timed(
                    metrics,
                    'extraction',
                    lambda: reporter.analyze_source(file_content, metrics=metrics),
                )
                preview_entry = _cache_preview(source_vendor, raw_content, analysis, os.path.basename(file.filename))
            else:
                analysis = preview_entry.analysis
            if metrics is not None:
                metrics.set_metadata('analysis_cache_hit', analysis_cache_hit)
            report = _timed(metrics, 'web_preview_construction', lambda: normalize_web_report(reporter.build_preview(analysis), source_vendor, copy=False))
            response = {
                'success': True,
                'preview_id': preview_entry.preview_id,
                **report,
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
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise ValueError('Collection request must be a JSON object.')
        collector = source_collectors.get(payload.get('vendor'))
        return collector, collector.validate_options(payload.get('connection'))

    @app.route('/api/collection/test', methods=['POST'])
    def test_collection_connection():
        try:
            collector, options = collection_options()
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        try:
            collector.test_connection(options)
            return jsonify({'success': True, 'status': 'CONNECTED'})
        except Exception:
            return jsonify({'success': False, 'error': 'Connection failed. Check the device and credentials.'}), 502

    @app.route('/api/collection/collect', methods=['POST'])
    def collect_configuration():
        try:
            collector, options = collection_options()
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        try:
            source = collector.collect(options)
            if source.status == CollectionStatus.FAILED or not source.source_text.strip():
                return jsonify({'success': False, 'error': 'Collection returned no usable source.'}), 502
            snapshot = make_snapshot(source)
            raw = snapshot['source_text'].encode('utf-8')
            reporter = source_reporters.get(source.vendor_id)
            collection_warnings = tuple(snapshot['warnings'])
            entry = _lookup_source_preview(source.vendor_id, raw, collection_status=source.status,
                                           collection_warnings=collection_warnings,
                                           collection_method=source.method)
            if entry is None:
                analysis = reporter.analyze_source(snapshot['source_text'])
                entry = _cache_preview(source.vendor_id, raw, analysis, source.source_name,
                                       collection_status=source.status,
                                       collection_warnings=collection_warnings, collection_method=source.method)
            else:
                analysis = entry.analysis
            return jsonify({
                'success': True,
                'preview_id': entry.preview_id,
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
            source_bytes = source.source_text.encode('utf-8')
            collection_warnings = tuple(source.warnings)
            entry = _lookup_source_preview(source.vendor_id, source_bytes, collection_status=source.status,
                                           collection_warnings=collection_warnings,
                                           collection_method=source.method)
            if entry is None:
                analysis = reporter.analyze_source(source.source_text)
                entry = _cache_preview(source.vendor_id, source_bytes, analysis, source.source_name,
                                       collection_status=source.status, collection_warnings=collection_warnings,
                                       collection_method=source.method)
            else:
                analysis = entry.analysis
            return jsonify({'success': True, 'vendor_id': source.vendor_id, 'preview_id': entry.preview_id,
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
            payload = request.get_json(silent=True) or {}
            source_vendor = request.form.get('source_vendor') or payload.get('source_vendor') or 'fortigate'
            preview_id = request.form.get('preview_id') or payload.get('preview_id') or ''
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

            uploaded_file = request.files.get('file')
            raw_content = (
                _timed(metrics, 'request decode', uploaded_file.read)
                if uploaded_file is not None and uploaded_file.filename != ''
                else None
            )
            preview_entry = (
                _timed(
                    metrics,
                    'cache lookup',
                    lambda: _lookup_preview(preview_id, source_vendor, raw_content),
                )
                if preview_id
                else None
            )
            if preview_entry is None and raw_content is not None:
                preview_entry = _timed(
                    metrics,
                    'cache lookup',
                    lambda: _lookup_source_preview(source_vendor, raw_content),
                )
            if preview_entry is not None:
                analysis = (
                    preview_entry.analysis
                    if profile is ExcelExportProfile.FAST or source_vendor == "fortigate"
                    else _clone_preview(preview_entry)
                )
            else:
                if raw_content is None:
                    return jsonify({'error': 'A configuration file or valid preview_id is required for Excel extraction'}), 400
                file_content = _timed(
                    metrics,
                    'decode',
                    lambda: _decode_configuration(raw_content),
                )
                analysis = _timed(
                    metrics,
                    'extraction/fallback extraction',
                    lambda: _extract_source_config(source_vendor, file_content),
                )

            workbook = io.BytesIO()
            export_started = perf_counter()
            source_name = os.path.basename(uploaded_file.filename) if uploaded_file is not None and uploaded_file.filename else (preview_entry.source_name if preview_entry else None)
            export_metrics = (
                ExcelExportMetrics()
                if metrics is not None and profile is ExcelExportProfile.FAST and source_vendor == 'fortigate'
                else None
            )
            export_options = {'profile': profile, 'source_name': source_name}
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
                    bool(preview_entry),
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

    @app.route('/api/diagnostics', methods=['POST'])
    def run_diagnostics():
        """Plan diagnostics are unavailable without a migration planner."""
        return _conversion_unavailable()

