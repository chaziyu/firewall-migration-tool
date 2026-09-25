from __future__ import annotations

from typing import Protocol

from ..model.selected_sections import (
    FGNACPolicy, FGAddress6Template, FGAddress6TemplateSegment, FGAddress6TemplateValue,
    FGIPSSettings, FGKMIPServer, FGKMIPServerEntry, FGKerberosKeytab, FGRouterSettings,
    FGSDNProxy, FGOnDemandSniffer, FGAffinityInterrupt, FGSerialPort,
    FGFirewallRegion, FGVendorMAC,
)
from ..nodes import CommandNode
from .common import evaluate_config, evaluate_edit, get_child_config, iter_section_configs, iter_section_edits, source_model_kwargs
from .section_index import SectionIndex


class Config(Protocol):
    nac_policies: list[FGNACPolicy]
    address6_templates: list[FGAddress6Template]
    ips_settings: list[FGIPSSettings]
    kmip_servers: list[FGKMIPServer]
    kerberos_keytabs: list[FGKerberosKeytab]
    router_settings: list[FGRouterSettings]
    sdn_proxies: list[FGSDNProxy]
    on_demand_sniffers: list[FGOnDemandSniffer]
    affinity_interrupts: list[FGAffinityInterrupt]
    serial_ports: list[FGSerialPort]
    firewall_regions: list[FGFirewallRegion]
    vendor_macs: list[FGVendorMAC]


def extract_selected_sections(tree: SectionIndex, config: Config) -> None:
    _simple_edits(tree, config, "user nac-policy", "nac_policies", FGNACPolicy)
    _extract_address6_templates(tree, config)
    _extract_config_settings(tree, config, "ips settings", "ips_settings", FGIPSSettings)
    _extract_kmip(tree, config)
    _extract_keytabs(tree, config)
    _extract_config_settings(tree, config, "router setting", "router_settings", FGRouterSettings)
    _extract_sdn_proxy(tree, config)
    _simple_edits(tree, config, "firewall on-demand-sniffer", "on_demand_sniffers", FGOnDemandSniffer)
    _simple_edits(tree, config, "system affinity-interrupt", "affinity_interrupts", FGAffinityInterrupt, numeric_id=True)
    _simple_edits(tree, config, "system serial-port", "serial_ports", FGSerialPort)
    _simple_edits(tree, config, "firewall region", "firewall_regions", FGFirewallRegion, numeric_id=True)
    _simple_edits(tree, config, "firewall vendor-mac", "vendor_macs", FGVendorMAC, numeric_id=True)


def _simple_edits(tree, config, path, destination, model_type, *, numeric_id=False):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(
            evaluation, model_type=model_type,
            vdom=source.vdom if "vdom" in model_type.model_fields else None,
        )
        if numeric_id:
            try:
                values["id"] = int(source.edit.name)
            except ValueError:
                values["id"] = None
                values["raw_extra"]["unparsed_id"] = source.edit.name
        elif "name" in model_type.model_fields:
            values["name"] = source.edit.name
        getattr(config, destination).append(model_type(**values))


def _extract_config_settings(tree, config, path, destination, model_type):
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=model_type, vdom=source.vdom)
        getattr(config, destination).append(model_type(**values))


def _extract_address6_templates(tree, config):
    path = "firewall address6-template"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGAddress6Template, name=source.edit.name, vdom=source.vdom)
        segments = get_child_config(source.edit, "subnet-segment")
        if segments is not None:
            values["segments"] = []
            for edit in segments.edits:
                segment_path = f"{path} subnet-segment"
                segment_eval = evaluate_edit(segment_path, edit)
                segment_values = source_model_kwargs(segment_eval, model_type=FGAddress6TemplateSegment)
                try:
                    segment_values["id"] = int(edit.name)
                except ValueError:
                    segment_values["id"] = None
                    segment_values["raw_extra"]["unparsed_id"] = edit.name
                child = get_child_config(edit, "values")
                if child is not None:
                    segment_values["values"] = []
                    for value_edit in child.edits:
                        value_eval = evaluate_edit(f"{segment_path} values", value_edit)
                        value_attributes = source_model_kwargs(value_eval, model_type=FGAddress6TemplateValue, name=value_edit.name)
                        segment_values["values"].append(FGAddress6TemplateValue(**value_attributes))
                values["segments"].append(FGAddress6TemplateSegment(**segment_values))
        config.address6_templates.append(FGAddress6Template(**values))


def _secret_present(edit, key):
    present = False
    for command in edit.commands:
        if isinstance(command, CommandNode) and command.key == key:
            if command.operation.lower() in {"set", "append"}:
                present = True
            elif command.operation.lower() == "unset":
                present = False
    return present


def _extract_kmip(tree, config):
    path = "vpn kmip-server"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGKMIPServer, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        server_list = get_child_config(source.edit, "server-list")
        if server_list is not None:
            values["server_list"] = []
            for edit in server_list.edits:
                child_eval = evaluate_edit(f"{path} server-list", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGKMIPServerEntry)
                try:
                    child_values["id"] = int(edit.name)
                except ValueError:
                    child_values["id"] = None
                    child_values["raw_extra"]["unparsed_id"] = edit.name
                values["server_list"].append(FGKMIPServerEntry(**child_values))
        config.kmip_servers.append(FGKMIPServer(**values))


def _extract_keytabs(tree, config):
    path = "user krb-keytab"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGKerberosKeytab, name=source.edit.name, vdom=source.vdom)
        values["keytab_configured"] = _secret_present(source.edit, "keytab")
        values["raw_extra"].pop("keytab", None)
        config.kerberos_keytabs.append(FGKerberosKeytab(**values))


def _extract_sdn_proxy(tree, config):
    path = "system sdn-proxy"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGSDNProxy, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        config.sdn_proxies.append(FGSDNProxy(**values))
