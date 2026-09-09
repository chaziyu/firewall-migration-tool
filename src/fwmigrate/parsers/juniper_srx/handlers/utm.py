"""Source-only extraction for Junos UTM policy/profile composition."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperSourceHierarchyItem,
    JuniperUTMAntivirusProfile,
    JuniperUTMWebFilteringProfile,
    JuniperUTMContentFilteringProfile,
    JuniperUTMAntiSpamProfile,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_utm_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "security" or toks[2].lower() != "utm":
        return False

    # Junos UTM antivirus profiles live below feature-profile anti-virus.
    # Keep the complete command in source_attributes while exposing the small,
    # verified subset needed by extraction consumers.
    if (
        len(toks) >= 7
        and toks[3].lower() == "feature-profile"
        and toks[4].lower() in {"anti-virus", "antivirus"}
        and toks[5].lower() == "profile"
    ):
        name = toks[6]
        profile = context.antivirus_profiles.setdefault(
            name, JuniperUTMAntivirusProfile(name=name)
        )
        rest = toks[7:]
        if rest:
            key = rest[0].lower()
            values = extract_value_list(rest[1:])
            safe_values = sanitize_tokens(values)
            if key == "type" and safe_values:
                profile.engine_type = safe_values[0]
            elif key in {"scan-options", "scan-option", "scan"}:
                option, option_values = _option_values(safe_values, key)
                profile.scan_behavior.setdefault(option, []).extend(option_values)
            elif key in {"fallback-options", "fallback-option", "fallback"}:
                option, option_values = _option_values(safe_values, key)
                profile.fallback_behavior.setdefault(option, []).extend(option_values)
            elif key in {"file-extension", "file-extensions", "file-type", "file-types"}:
                profile.file_controls.extend(v for v in safe_values if v not in profile.file_controls)
            elif key in {"mime", "mime-type", "mime-types"}:
                profile.mime_types.extend(v for v in safe_values if v not in profile.mime_types)
            else:
                profile.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(
                    sanitize_source_attributes({"raw": cmd.raw_sanitized})
                )
        profile.source_attributes.update(
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )
        cmd.consumed, cmd.handler = True, "utm"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if (
        len(toks) >= 7
        and toks[3].lower() == "feature-profile"
        and toks[4].lower() in {"anti-spam", "antispam"}
        and toks[5].lower() == "profile"
    ):
        name = toks[6]
        profile = context.anti_spam_profiles.setdefault(
            name, JuniperUTMAntiSpamProfile(name=name)
        )
        rest = toks[7:]
        if rest:
            key = rest[0].lower()
            values = sanitize_tokens(extract_value_list(rest[1:]))
            if key in {"server", "servers", "smtp-server", "mail-server"}:
                profile.servers.extend(v for v in values if v not in profile.servers)
            elif key in {"action", "default-action"}:
                profile.actions.extend(v for v in values if v not in profile.actions)
            else:
                profile.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(
                    sanitize_source_attributes({"raw": cmd.raw_sanitized})
                )
        profile.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
        cmd.consumed, cmd.handler = True, "utm"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if (
        len(toks) >= 7
        and toks[3].lower() == "feature-profile"
        and toks[4].lower() in {"content-filtering", "content-filter"}
        and toks[5].lower() == "profile"
    ):
        name = toks[6]
        profile = context.content_filtering_profiles.setdefault(
            name, JuniperUTMContentFilteringProfile(name=name)
        )
        rest = toks[7:]
        if rest:
            key = rest[0].lower()
            values = sanitize_tokens(extract_value_list(rest[1:]))
            if key in {"content-type", "content-types", "file-type", "file-types"}:
                profile.content_types.extend(v for v in values if v not in profile.content_types)
            elif key in {"action", "default-action"}:
                profile.actions.extend(v for v in values if v not in profile.actions)
            else:
                profile.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(
                    sanitize_source_attributes({"raw": cmd.raw_sanitized})
                )
            profile.syntax_variant = key
        profile.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
        cmd.consumed, cmd.handler = True, "utm"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if (
        len(toks) >= 7
        and toks[3].lower() == "feature-profile"
        and toks[4].lower() in {"web-filtering", "webfiltering"}
        and toks[5].lower() == "profile"
    ):
        name = toks[6]
        profile = context.web_filtering_profiles.setdefault(
            name, JuniperUTMWebFilteringProfile(name=name)
        )
        rest = toks[7:]
        if rest:
            key = rest[0].lower()
            values = sanitize_tokens(extract_value_list(rest[1:]))
            field = {
                "url-category": profile.url_categories,
                "url-categories": profile.url_categories,
                "custom-url-category": profile.custom_url_lists,
                "custom-url-list": profile.custom_url_lists,
                "action": profile.actions,
                "log": profile.logging,
                "logging": profile.logging,
            }.get(key)
            if field is not None:
                field.extend(v for v in values if v not in field)
            else:
                profile.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(
                    sanitize_source_attributes({"raw": cmd.raw_sanitized})
                )
        profile.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
        cmd.consumed, cmd.handler = True, "utm"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    name = toks[3] if len(toks) > 3 else "__global__"
    item = context.utm_policies.setdefault(name, JuniperSourceHierarchyItem(name=name))
    item.settings["_".join(sanitize_tokens(toks[4:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed, cmd.handler = True, "utm"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _option_values(values: list[str], parent: str) -> tuple[str, list[str]]:
    """Split an option container into its child key and repeated values."""
    if len(values) > 1:
        return values[0].replace("-", "_"), values[1:]
    return parent.replace("-", "_"), values
