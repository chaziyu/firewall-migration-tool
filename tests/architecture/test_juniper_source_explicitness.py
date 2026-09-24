from typing import get_args

from pydantic import BaseModel

from fwmigrate.vendors.juniper_srx import model


INTERNAL_BOOLEAN_DEFAULTS = {
    ("JuniperEffectiveProvenance", "overridden"),
    ("JuniperEffectiveProvenance", "excluded"),
    ("JuniperEffectiveProvenance", "inactive"),
    ("JuniperGroupApplication", "active"),
    ("JuniperEffectiveCandidate", "effective"),
    ("JuniperEffectiveCandidate", "shadowed"),
    ("JuniperEffectiveCandidate", "excluded"),
    ("JuniperEffectiveCandidate", "inactive"),
    ("JuniperGroupStatement", "active"),
    ("JuniperGroupNode", "wildcard"),
}


def test_source_boolean_fields_do_not_default_to_false_or_true():
    for cls in vars(model).values():
        if (not isinstance(cls, type) or cls.__module__ != model.__name__
                or not issubclass(cls, BaseModel)):
            continue
        for name, field in cls.model_fields.items():
            if bool not in (field.annotation, *get_args(field.annotation)):
                continue
            if field.default is False or field.default is True:
                assert (cls.__name__, name) in INTERNAL_BOOLEAN_DEFAULTS


def test_structural_source_fields_are_required_and_inferred_fields_are_absent():
    required = {
        model.JuniperInterfaceAddress: "family",
        model.JuniperFirewallFilter: "family",
        model.JuniperPolicy: "policy_scope",
        model.JuniperRouteNextHop: "qualified",
        model.JuniperNATPool: "nat_type",
        model.JuniperNATRule: "nat_type",
        model.JuniperNATRuleSet: "nat_type",
        model.JuniperNTPServer: "role",
        model.JuniperAddress: "address_book",
        model.JuniperAddressSet: "address_book",
        model.JuniperAddressBook: "name",
        model.JuniperAddressSetMember: "member_type",
    }
    for cls, field in required.items():
        assert cls.model_fields[field].is_required()

    removed = {
        model.JuniperRoute: {"discard", "reject", "receive", "no_install"},
        model.JuniperAddress: {"disabled"},
        model.JuniperAddressSet: {"disabled"},
        model.JuniperAddressSetMember: {"disabled"},
        model.JuniperZone: {"disabled"},
        model.JuniperScreenOption: {"disabled"},
        model.JuniperScreenProfile: {"disabled"},
        model.JuniperApplicationTerm: {"disabled"},
        model.JuniperApplication: {"disabled"},
        model.JuniperApplicationSet: {"disabled"},
        model.JuniperPolicy: {"disabled"},
        model.JuniperNATRule: {"nat_family"},
        model.JuniperNATRuleSet: {"disabled"},
        model.JuniperPersistentNAT: {"enabled"},
        model.JuniperVPNMonitor: {"enabled"},
        model.JuniperIPSecVPN: {"disabled"},
        model.JuniperSourceHierarchyItem: {"disabled"},
        model.JuniperUTMAntivirusProfile: {"disabled"},
        model.JuniperUTMWebFilteringProfile: {"disabled"},
        model.JuniperUTMContentFilteringProfile: {"disabled"},
        model.JuniperUTMAntiSpamProfile: {"disabled"},
        model.JuniperPrefixList: {"disabled"},
        model.JuniperVLAN: {"disabled"},
        model.JuniperClusterPreempt: {"enabled"},
    }
    for cls, fields in removed.items():
        assert fields.isdisjoint(cls.model_fields)


def test_nullable_source_presence_fields_start_unset():
    fields = {
        model.JuniperInterfaceAddress: ("primary", "preferred"),
        model.JuniperInterfaceUnit: ("disabled",),
        model.JuniperInterface: ("disabled",),
        model.JuniperZone: ("tcp_rst",),
        model.JuniperPolicy: (
            "source_address_excluded", "destination_address_excluded",
            "log_session_init", "log_session_close", "count",
        ),
        model.JuniperRoute: ("disabled", "retain"),
        model.JuniperNTPServer: ("preferred",),
        model.JuniperIKEPolicy: ("has_pre_shared_key",),
        model.JuniperSSHSettings: ("enabled",),
        model.JuniperNETCONFSettings: ("enabled",),
        model.JuniperWebManagementSettings: ("http_enabled", "https_enabled"),
    }
    for cls, names in fields.items():
        for name in names:
            assert cls.model_fields[name].default is None
