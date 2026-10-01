"""Junos set-format collection over SSH."""

import re

from fwmigrate.vendors.juniper_srx.extraction import sanitize_junos_source_text
from fwmigrate.vendors.juniper_srx.tokenizer import JuniperSetTokenizer

from .contracts import (
    CollectedSource,
    CollectionError,
    CollectionPart,
    CollectionStatus,
    SSH_FIELDS,
    validate_connection,
)


class JuniperSRXCollector:
    vendor_id = "juniper_srx"
    method = "ssh"
    fields = SSH_FIELDS

    def validate_options(self, connection):
        return validate_connection(connection, port=22)

    def _connect(self, options):
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise CollectionError("Live collection requires the collection extra (netmiko).") from exc
        return ConnectHandler(device_type="juniper_junos", host=options["host"], port=options["port"],
                              username=options["username"], password=options["password"],
                              conn_timeout=15, auth_timeout=15, banner_timeout=15,
                              ssh_strict=True, system_host_keys=True)

    def test_connection(self, options):
        connection = self._connect(options)
        try:
            pass
        finally:
            connection.disconnect()

    def collect(self, options):
        connection = self._connect(options)
        try:
            content = connection.send_command("show configuration | display set", read_timeout=60)
        finally:
            connection.disconnect()
        if not content.strip():
            raise CollectionError("The device returned an empty configuration.")
        if re.search(r"(?im)^\s*(?:error\b|syntax error\b|unknown command\b|permission denied\b|authorization (?:failed|denied)\b)", content):
            raise CollectionError("The device rejected the configuration collection command.")
        if len(content.encode("utf-8")) > 25_000_000:
            raise CollectionError("The device configuration exceeds the size limit.")

        commands = JuniperSetTokenizer().tokenize(content)
        access_denied = any(command.access_denied for command in commands)
        status = CollectionStatus.PARTIAL if access_denied else CollectionStatus.SUCCESS
        part = CollectionPart(
            name="configuration",
            status="PERMISSION_DENIED" if access_denied else "SUCCESS_WITH_DATA",
            complete=not access_denied,
            count=len(commands),
        )
        warnings = (
            ("Configuration contains ACCESS-DENIED placeholders; collection is incomplete.",)
            if access_denied else ()
        )
        return CollectedSource(
            self.vendor_id,
            sanitize_junos_source_text(content),
            "live-juniper-srx.set",
            self.method,
            status=status,
            parts=(part,),
            warnings=warnings,
        )
