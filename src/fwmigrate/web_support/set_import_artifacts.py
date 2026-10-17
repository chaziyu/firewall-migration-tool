"""Internal approval envelopes for engineer-reviewed PAN-OS command uploads."""
import math
import time
import uuid

from fwmigrate.conversion.fortigate_to_palo_alto.application import (
    ArtifactEligibilityError, DESIGN_APPROVAL_TTL_SECONDS, target_devices, target_serial,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import RenderedMigration
from fwmigrate.deployment.panos_set_import import SetImportError, parse_set_upload
from fwmigrate.vendors.palo_alto.config_fingerprint import BASELINE_FORMAT, destination_fingerprint
from .artifact_signing import sign_envelope, verify_envelope
from .request_source import _require_complete_collection, analyze_request_source

SET_REVIEW = 'panos_set_review_v1'
SET_ARTIFACT = 'panos_set_import_v1'


def set_import_target(payload, parsed):
    entry = analyze_request_source(payload, 'palo_alto', target=True)
    _require_complete_collection(entry)
    devices = target_devices(entry.analysis)
    if not devices:
        raise SetImportError('Destination XML contains no selectable firewall device.')
    selected = payload.get('target_device') or (devices[0] if len(devices) == 1 else None)
    if not selected:
        return None, devices
    if selected not in devices:
        raise SetImportError('Select a device present in the destination XML.')
    serial = target_serial(entry.analysis, selected)
    if not serial:
        raise SetImportError('Destination XML must contain an explicit device serial.')
    scopes = [scope for scope in entry.analysis.config.scopes
              if (scope.device_serial or scope.device_name) == selected]
    if not scopes or any(scope.kind in {'template', 'template-stack', 'device-group'}
                         or scope.device_group or scope.template_stack for scope in scopes):
        raise SetImportError('Only standalone firewall destination evidence is supported.')
    if not set(parsed['vsys']) <= {scope.vsys for scope in scopes if scope.vsys}:
        raise SetImportError('A command references a VSYS absent from the selected destination.')
    host, port = payload.get('host'), payload.get('port', 22)
    if not isinstance(host, str) or not host.strip() or type(port) is not int or not 1 <= port <= 65535:
        raise SetImportError('Enter a destination host and valid SSH port before review.')
    return {'target_device': selected, 'target_serial': serial, 'config_digest': entry.source_digest,
            'baseline_sha256': destination_fingerprint(entry.evidence['source_text']), 'baseline_format': BASELINE_FORMAT,
            'host': host.strip().casefold(), 'port': port}, devices


def create_set_review(raw, filename, payload, key):
    parsed = parse_set_upload(raw)
    context, devices = set_import_target(payload, parsed)
    if context is None:
        return {'devices': devices, 'review': None}
    # Filenames are display metadata, never paths or credential-bearing evidence.
    filename = str(filename).replace('\\', '/').rsplit('/', 1)[-1]
    draft = {**parsed, 'filename': filename[:200], 'context': context, 'envelope_type': SET_REVIEW,
             'expires_at': time.time() + DESIGN_APPROVAL_TTL_SECONDS}
    return {'devices': devices, 'review': sign_envelope(draft, key)}


def _verify_set_envelope(value, key, kind):
    value = verify_envelope(value, key)
    expires = value.get('expires_at')
    if (value.get('envelope_type') != kind or type(expires) not in {int, float}
            or not math.isfinite(expires) or time.time() >= expires):
        raise ArtifactEligibilityError('Upload review has expired; review and approve the file again')
    commands = value['commands']
    if not isinstance(commands, list) or len(commands) != value['command_count']:
        raise ValueError('Invalid upload command count')
    if len(value['line_numbers']) != len(commands) or any(type(number) is not int or number < 1 for number in value['line_numbers']):
        raise ValueError('Invalid upload line numbers')
    parsed = parse_set_upload('\n'.join(commands).encode())
    if parsed['command_sha256'] != value['command_sha256'] or parsed['commands'] != commands:
        raise ValueError('Invalid upload command hash')
    return value


def approve_set_review(draft, digest, key):
    draft = _verify_set_envelope(draft, key, SET_REVIEW)
    if digest != draft['command_sha256']:
        raise ValueError('Upload review changed')
    return sign_envelope({**draft, 'envelope_type': SET_ARTIFACT, 'artifact_id': uuid.uuid4().hex,
                          'approved_at': time.time()}, key)


def verify_set_artifact(value, payload, key):
    value = _verify_set_envelope(value, key, SET_ARTIFACT)
    context = value['context']
    if (str(payload.get('host', '')).strip().casefold(), int(payload.get('port', 22))) != (context['host'], context['port']):
        raise ArtifactEligibilityError('Upload approval belongs to a different destination host or port')
    report = {'plan_status': 'READY', 'provenance': 'UPLOADED_SET',
              'validation_scope': 'syntax_and_engineer_review', 'command_sha256': value['command_sha256'],
              'line_numbers': value['line_numbers']}
    return RenderedMigration(tuple(value['commands']), report), context, None
