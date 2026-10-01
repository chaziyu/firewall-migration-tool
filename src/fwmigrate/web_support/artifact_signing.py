"""Authenticate browser-held envelopes using a deployment-wide HMAC key."""
import hashlib
import hmac
import json

from fwmigrate.conversion.fortigate_to_palo_alto.renderer import RenderedMigration


def sign_envelope(value, key):
    body = {name: item for name, item in value.items() if name != 'signature'}
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {**body, 'signature': hmac.new(key, encoded, hashlib.sha256).hexdigest()}


def verify_envelope(value, key):
    if not isinstance(value, dict) or not isinstance(value.get('signature'), str):
        raise ValueError('A signed workspace envelope is required')
    expected = sign_envelope(value, key)['signature']
    if not hmac.compare_digest(expected, value['signature']):
        raise ValueError('Workspace envelope signature is invalid')
    return value


def verify_artifact(value, key):
    value = verify_envelope(value, key)
    commands = value.get('commands')
    if not isinstance(commands, list) or any(not isinstance(item, str) for item in commands):
        raise ValueError('Artifact commands must be an array of strings')
    digest = hashlib.sha256('\n'.join(commands).encode('utf-8')).hexdigest()
    if (value.get('command_count') != len(commands) or value.get('command_sha256') != digest
            or value.get('report', {}).get('command_sha256') != digest):
        raise ValueError('Artifact command count or SHA-256 does not match')
    return RenderedMigration(tuple(commands), value['report'])
