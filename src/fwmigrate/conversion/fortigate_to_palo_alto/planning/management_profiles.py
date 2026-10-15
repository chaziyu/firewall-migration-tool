"""Reviewed device-scoped management profiles; permitted networks are never inferred."""
import hashlib

from ..models import PANMigrationStatus, PlannedManagementProfile
from ..target.profile import management_profile_groups


def management_profile_name(identity):
    return 'FG-MGMT-' + hashlib.sha256(identity.encode()).hexdigest()[:16]


def plan_management_profiles(source, options):
    groups = {group['identity']: group for group in management_profile_groups(source)}
    settings = options.conversion_settings.get('generated_management_profiles', {})
    if set(settings) - groups.keys():
        raise ValueError('Generated management profiles must select current scoped protocol groups')
    profiles = []
    for identity, values in sorted(settings.items()):
        group = groups[identity]
        protocols = tuple(identity.split('/', 1)[1].split(','))
        supported = set(protocols) <= {'ping', 'https', 'ssh', 'snmp', 'http', 'telnet'}
        profiles.append(PlannedManagementProfile(source_vdom=group['source_vdom'], source_kind='management_profile',
            source_object_type='management_profile', source_name=identity, target_name=management_profile_name(identity),
            status=PANMigrationStatus.SUPPORTED if supported else PANMigrationStatus.UNSUPPORTED,
            warnings=() if supported else ('Administrative protocols have no verified management-profile equivalent',),
            protocols=protocols, permitted_ips=tuple(values['permitted_ips'])))
    return tuple(profiles)
