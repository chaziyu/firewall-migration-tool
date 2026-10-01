"""Request-owned source evidence; no parsed configuration survives a request."""
from dataclasses import dataclass
import hashlib
import json
import os

from flask import request
from fwmigrate.collection import CollectionStatus
from fwmigrate.collection.snapshot import parse_snapshot, sanitize_source, make_snapshot
from fwmigrate.source_reporting import source_reporters
from .reporting import _decode_configuration


@dataclass(frozen=True)
class RequestSource:
    source_vendor: str
    source_digest: str
    analysis: object
    source_name: str | None = None
    collection_status: CollectionStatus | None = None
    evidence: dict | None = None


def analyze_request_source(payload, vendor, *, target=False):
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
            collected = parse_snapshot(json.dumps(evidence).encode('utf-8'))
            if collected.vendor_id != vendor:
                raise ValueError('Snapshot vendor does not match the requested vendor')
            text, name, status = collected.source_text, collected.source_name, collected.status
            evidence = make_snapshot(collected)
        else:
            if evidence.get('vendor') != vendor or not isinstance(evidence.get('source_text'), str):
                raise ValueError('Vendor-native source evidence is required')
            text = sanitize_source(vendor, evidence['source_text'])
            name = evidence.get('source_name')
            evidence = {'vendor': vendor, 'source_text': text, 'source_name': name}
    elif uploaded and uploaded.filename:
        text = sanitize_source(vendor, _decode_configuration(uploaded.read()))
        name = os.path.basename(uploaded.filename)
        evidence = {'vendor': vendor, 'source_text': text, 'source_name': name}
    else:
        raise ValueError('A vendor-native source file or snapshot is required')
    digest = hashlib.sha256(text.encode('utf-8') + b'\0' + vendor.encode('utf-8')).hexdigest()
    analysis = source_reporters.get(vendor).analyze_source(text)
    return RequestSource(vendor, digest, analysis, name, status, evidence)


def _clone_preview(entry):
    return entry.analysis


def _require_complete_collection(entry):
    if getattr(entry, 'collection_status', None) is not None and entry.collection_status != CollectionStatus.SUCCESS:
        raise ValueError('Migration requires a complete live collection; this source is PARTIAL or FAILED.')
