"""Cisco ASA configuration collection over SSH."""

import re

from fwmigrate.extraction.sanitize import sanitize_raw_text

from .contracts import CollectedSource, CollectionError, CollectionPart, CollectionStatus, SSH_FIELDS, validate_connection


def _connect(options):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise CollectionError("Live collection requires the collection extra (netmiko).") from exc
    return ConnectHandler(
        device_type="cisco_asa", host=options["host"], port=options["port"],
        username=options["username"], password=options["password"],
        conn_timeout=15, auth_timeout=15, banner_timeout=15,
        ssh_strict=True, system_host_keys=True,
    )


class CiscoASACollector:
    vendor_id = "cisco_asa"
    method = "ssh"
    fields = SSH_FIELDS

    def validate_options(self, connection):
        return validate_connection(connection, port=22)

    def test_connection(self, options):
        connection = _connect(options)
        try:
            pass
        finally:
            connection.disconnect()

    def collect(self, options) -> CollectedSource:
        connection = _connect(options)
        parts = []
        warnings = []
        sections = []
        multi_context = False
        try:
            mode = connection.send_command("show mode", read_timeout=30)
            multi_context = bool(re.search(r"context\s+mode\s*:\s*multiple\b|\bmultiple\s+context\s+mode\b", mode, re.I))
            if not multi_context:
                content = connection.send_command("show running-config", read_timeout=60)
                if not content.strip():
                    raise CollectionError("The device returned an empty configuration.")
                parts.append(CollectionPart("running-config", "SUCCESS", True, 1))
                sections.append(content)
            else:
                connection.send_command("changeto system", read_timeout=30)
                system = connection.send_command("show running-config", read_timeout=60)
                if not system.strip():
                    raise CollectionError("The system context returned an empty configuration.")
                parts.append(CollectionPart("system/running-config", "SUCCESS", True, 1))
                sections.extend(("changeto system", system))
                contexts = list(dict.fromkeys(re.findall(r"(?im)^\s*context\s+([A-Za-z0-9_.-]+)\s*$", system)))
                if not contexts:
                    warnings.append("Multiple-context mode was detected, but no context names were found in the system configuration.")
                    parts.append(CollectionPart("contexts", "FAILED", False, 0))
                else:
                    parts.append(CollectionPart("contexts", "SUCCESS", True, len(contexts)))
                for context in contexts:
                    try:
                        connection.send_command(f"changeto context {context}", read_timeout=30)
                        content = connection.send_command("show running-config", read_timeout=60)
                    except Exception:
                        warnings.append(f"Could not collect context {context}.")
                        parts.append(CollectionPart(f"context/{context}/running-config", "FAILED", False, 0))
                        continue
                    if not content.strip():
                        warnings.append(f"Context {context} returned an empty configuration.")
                        parts.append(CollectionPart(f"context/{context}/running-config", "EMPTY", False, 0))
                        continue
                    sections.extend((f"changeto context {context}", content))
                    parts.append(CollectionPart(f"context/{context}/running-config", "SUCCESS", True, 1))
        finally:
            if multi_context:
                try:
                    connection.send_command("changeto system", read_timeout=30)
                except Exception:
                    pass
            connection.disconnect()
        content = "\n".join(sections)
        if not content.strip():
            raise CollectionError("The device returned an empty configuration.")
        if len(content.encode("utf-8")) > 25_000_000:
            raise CollectionError("The device configuration exceeds the size limit.")
        incomplete = any(not part.complete for part in parts)
        return CollectedSource("cisco_asa", sanitize_raw_text(content), "live-cisco-asa.cfg", "ssh",
                               CollectionStatus.PARTIAL if incomplete else CollectionStatus.SUCCESS,
                               {"multi_context": multi_context}, tuple(parts), tuple(warnings))


_collector = CiscoASACollector()
test_connection = _collector.test_connection
collect = _collector.collect
