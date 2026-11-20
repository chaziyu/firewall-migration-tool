"""Validate browser-held workspace envelopes and artifact command integrity."""
import hashlib

from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import RenderedMigration


def verify_envelope(value):
    if not isinstance(value, dict):
        raise ValueError('A workspace envelope is required')
    return value


def verify_artifact(value):
    value = verify_envelope(value)
    if not isinstance(value.get('artifact_id'), str) or value.get('envelope_type') is not None:
        raise ValueError('A migration artifact is required')
    commands = value.get('commands')
    if not isinstance(commands, list) or any(not isinstance(item, str) for item in commands):
        raise ValueError('Artifact commands must be an array of strings')
    report = value.get('report')
    if not isinstance(report, dict):
        raise ValueError('A migration artifact is required')
    digest = hashlib.sha256('\n'.join(commands).encode('utf-8')).hexdigest()
    if (value.get('command_count') != len(commands) or value.get('command_sha256') != digest
            or report.get('command_sha256') != digest):
        raise ValueError('Artifact command count or SHA-256 does not match')
    return RenderedMigration(tuple(commands), report)
