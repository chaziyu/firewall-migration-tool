"""Request-owned source evidence; no parsed configuration survives a request."""
from dataclasses import dataclass
import hashlib
import json
import os

from flask import request
from fwmigrate.collection import CollectionStatus
from fwmigrate.collection.snapshot import FORMAT, MAX_BYTES, parse_snapshot, sanitize_source, make_snapshot
from fwmigrate.source_reporting import source_reporters
from .reporting import SourceSizeError, _decode_configuration, _timed


@dataclass(frozen=True)
class RequestSource:
    source_vendor: str
    source_digest: str
    analysis: object
    source_name: str | None = None
    collection_status: CollectionStatus | None = None
    evidence: dict | None = None


def _ensure_source_size(text: str) -> str:
    if len(text) > MAX_BYTES or len(text.encode("utf-8")) > MAX_BYTES:
        raise SourceSizeError("Source configuration exceeds the size limit.")
    return text


def _read_uploaded_source(uploaded) -> str:
    raw = uploaded.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise SourceSizeError("Source configuration exceeds the size limit.")
    return _decode_configuration(raw)


def analyze_request_source(payload, vendor, *, target=False, metrics=None):
    if not isinstance(payload, dict):
        raise ValueError('Source request must be an object')
    evidence = payload.get('target_source' if target else 'source')
    uploaded = request.files.get('target_file' if target else 'file')
    if isinstance(evidence, str):
        try: evidence = json.loads(evidence)
        except json.JSONDecodeError as exc: raise ValueError('Invalid source evidence') from exc
    status = None
    name = None
    if evidence is not None:
        if not isinstance(evidence, dict):
            raise ValueError('Source evidence must be an object')
        if evidence.get('format'):
            raw_snapshot = json.dumps(evidence).encode('utf-8')
            if len(raw_snapshot) > MAX_BYTES:
                raise SourceSizeError('Snapshot exceeds the size limit')
            collected = _timed(metrics, 'snapshot validation and sanitization', lambda: parse_snapshot(raw_snapshot))
            del raw_snapshot
            if collected.vendor_id != vendor:
                raise ValueError('Snapshot vendor does not match the requested vendor')
            text, name, status = collected.source_text, collected.source_name, collected.status
            evidence = make_snapshot(collected)
        else:
            if evidence.get('vendor') != vendor or not isinstance(evidence.get('source_text'), str):
                raise ValueError('Vendor-native source evidence is required')
            name = evidence.get('source_name')
            if name is not None and (not isinstance(name, str) or len(name) > 255):
                raise ValueError('Source name must be a string of at most 255 characters')
            text = _timed(metrics, 'source sanitization', lambda: sanitize_source(vendor, _ensure_source_size(evidence['source_text'])))
            evidence = {'vendor': vendor, 'source_text': text, 'source_name': name}
    elif uploaded and uploaded.filename:
        text = _timed(metrics, 'source decode and sanitization', lambda: sanitize_source(vendor, _read_uploaded_source(uploaded)))
        name = os.path.basename(uploaded.filename)
        evidence = {'vendor': vendor, 'source_text': text, 'source_name': name}
    else:
        raise ValueError('A vendor-native source file or snapshot is required')
    hasher = hashlib.sha256()
    hasher.update(text.encode('utf-8'))
    hasher.update(b'\0')
    hasher.update(vendor.encode('utf-8'))
    digest = hasher.hexdigest()
    options = {'metrics': metrics} if metrics is not None else {}
    analysis = _timed(metrics, 'source analysis', lambda: source_reporters.get(vendor).analyze_source(text, **options))
    return RequestSource(vendor, digest, analysis, name, status, evidence)


def _clone_preview(entry):
    return entry.analysis


def _require_complete_collection(entry):
    if getattr(entry, 'collection_status', None) is not None and entry.collection_status != CollectionStatus.SUCCESS:
        raise ValueError('Migration requires a complete live collection; this source is PARTIAL or FAILED.')
    evidence = getattr(entry, 'evidence', None)
    if isinstance(evidence, dict) and evidence.get('format') == FORMAT and any(
        not part.get('complete') or part.get('status') not in {'SUCCESS', 'SUCCESS_WITH_DATA', 'SUCCESS_EMPTY', 'EMPTY'}
        for part in evidence.get('parts', ())
    ):
        raise ValueError('Migration requires a complete live collection; one or more collection parts are incomplete.')
