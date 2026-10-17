"""Read reviewed PAN-OS command files, not source configuration models."""
import hashlib
import shlex

from fwmigrate.extraction.sanitize import is_sensitive_key, sanitize_raw_text

MAX_SET_BYTES = 5_000_000
MAX_SET_COMMANDS = 50_000
MAX_SET_LINE = 16_384


class SetImportError(ValueError):
    """Safe input diagnostics; never include uploaded command text."""


def _values(values):
    if values[:1] == ['['] and values[-1:] == [']']:
        values = values[1:-1]
        return bool(values) and not any(value in {'[', ']'} for value in values)
    return len(values) == 1 and values[0] not in {'[', ']'}


def _vsys_path(path):
    match path:
        case ['address', _, ('ip-netmask' | 'ip-range' | 'fqdn'), _]:
            return True
        case ['address-group', _, 'static', *values] | ['service-group', _, 'members', *values]:
            return _values(values)
        case ['service', _, 'protocol', ('tcp' | 'udp')]:
            return True
        case ['service', _, 'protocol', ('tcp' | 'udp'), ('port' | 'source-port'), _]:
            return True
        case ['zone', _, 'network', 'layer3', *values] | ['import', 'network', 'interface', *values]:
            return _values(values)
        case ['schedule', _, 'schedule-type', 'recurring']:
            return True
        case ['schedule', _, 'schedule-type', 'recurring', 'weekly', _, *values]:
            return _values(values)
        case ['schedule', _, 'schedule-type', 'recurring', 'daily', *values] | ['schedule', _, 'schedule-type', 'non-recurring', *values]:
            return _values(values)
        case ['rulebase', 'security', 'rules', _, leaf, *values]:
            if leaf in {'from', 'to', 'source', 'destination', 'service', 'application', 'source-user'}:
                return _values(values)
            if leaf == 'profile-setting':
                return values[:1] == ['group'] and _values(values[1:])
            return leaf in {'action', 'schedule', 'negate-source', 'negate-destination', 'disabled', 'description', 'log-start', 'log-end'} and len(values) == 1
        case ['rulebase', 'nat', 'rules', _, leaf, *values]:
            if leaf in {'from', 'to', 'source', 'destination'}:
                return _values(values)
            if leaf in {'nat-type', 'service', 'to-interface'}:
                return len(values) == 1
            if leaf == 'destination-translation':
                return len(values) == 2 and values[0] in {'translated-address', 'translated-port'}
            if leaf == 'source-translation' and values[:1] == ['dynamic-ip-and-port']:
                return (values[1:3] == ['interface-address', 'interface'] and len(values) == 4
                        or values[1:2] == ['translated-address'] and _values(values[2:]))
    return False


def _network_path(path):
    match path:
        case ['profiles', 'interface-management-profile', _, leaf, *values]:
            if leaf == 'permitted-ip':
                return len(values) == 1
            return leaf in {'ping', 'https', 'ssh', 'snmp', 'http', 'telnet', 'http-ocsp', 'response-pages', 'userid-service', 'userid-syslog-listener-ssl', 'userid-syslog-listener-udp'} and values in (['yes'], ['no'])
        case ['interface', ('ethernet' | 'aggregate-ethernet'), _, 'layer3', *tail]:
            if tail[:1] == ['units'] and len(tail) >= 2:
                tail = tail[2:]
            return (not tail or len(tail) == 2 and tail[0] in {'ip', 'tag', 'interface-management-profile'}
                    or len(tail) == 3 and tail[0] == 'lacp' and tail[1] in {'enable', 'mode'})
        case ['interface', 'ethernet', _, 'aggregate-group', _]:
            return True
        case ['interface', ('loopback' | 'tunnel'), 'units', _, *tail]:
            return not tail or len(tail) == 2 and tail[0] in {'ip', 'interface-management-profile'}
        case ['virtual-router', _]:
            return True
        case ['virtual-router', _, 'interface', *values]:
            return _values(values)
        case ['virtual-router', _, 'routing-table', 'ip', 'static-route', _, *tail]:
            return (len(tail) == 2 and tail[0] in {'destination', 'interface', 'admin-dist'}
                    or tail in (['nexthop', 'discard'], ['nexthop', 'none'])
                    or len(tail) == 3 and tail[:2] == ['nexthop', 'ip-address'])
        case ['dhcp', 'interface', _, 'server', *tail]:
            return (len(tail) == 2 and tail[0] == 'mode'
                    or tail[:1] == ['ip-pool'] and _values(tail[1:])
                    or tail == ['option', 'lease', 'unlimited']
                    or len(tail) == 4 and tail[:3] == ['option', 'lease', 'timeout']
                    or len(tail) == 3 and tail[0] == 'option' and tail[1] in {'gateway', 'subnet-mask'}
                    or len(tail) == 4 and tail[:2] == ['option', 'dns'] and tail[2] in {'primary', 'secondary'})
        case ['ike', 'crypto-profiles', ('ike-crypto-profiles' | 'ipsec-crypto-profiles'), _, *tail]:
            return (tail[:1] in (['encryption'], ['hash'], ['dh-group']) and _values(tail[1:])
                    or tail[:2] in (['esp', 'encryption'], ['esp', 'authentication']) and _values(tail[2:])
                    or len(tail) == 3 and tail[0] == 'lifetime' and tail[1] in {'seconds', 'minutes', 'hours', 'days'})
    return False


def validate_set_commands(commands):
    scopes = set()
    for number, command in commands:
        reason = None
        if len(command) > MAX_SET_LINE:
            reason = 'Command exceeds the line length limit'
        elif any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in '\u2028\u2029' for char in command):
            reason = 'Unsafe control character'
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|`')
            lexer.whitespace = ' '
            lexer.whitespace_split = True
            lexer.commenters = ''
            tokens = list(lexer)
        except ValueError:
            tokens = []
            reason = reason or 'Malformed quoting'
        if any(is_sensitive_key(token) for token in tokens) or sanitize_raw_text(command) != command:
            reason = 'Secret-bearing commands are not supported'
        if any(token and all(char in ';&|`' for char in token) for token in tokens):
            reason = reason or 'Command separators are not supported'
        allowed = False
        match tokens:
            case ['set', 'vsys', scope, *path]:
                allowed = _vsys_path(path)
                scopes.add(scope)
            case ['set', 'network', *path]:
                allowed = _network_path(path)
        if reason or not allowed:
            raise SetImportError(f'Line {number}: {reason or "Unsupported command path; use explicit VSYS and supported configuration paths"}.')
    return sorted(scopes)


def parse_set_upload(raw):
    if not raw or len(raw) > MAX_SET_BYTES:
        raise SetImportError('Choose a nonempty .set file of at most 5 MB.')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise SetImportError('The .set file must use UTF-8 encoding.') from None
    lines = [(number, line) for number, line in enumerate(text.replace('\r\n', '\n').split('\n'), 1) if line.strip()]
    if not lines or len(lines) > MAX_SET_COMMANDS:
        raise SetImportError('The file must contain between 1 and 50,000 commands.')
    scopes = validate_set_commands(lines)
    commands = [command for _, command in lines]
    return {'commands': commands, 'line_numbers': [number for number, _ in lines], 'vsys': scopes,
            'file_sha256': hashlib.sha256(raw).hexdigest(), 'command_count': len(commands),
            'command_sha256': hashlib.sha256('\n'.join(commands).encode()).hexdigest()}
