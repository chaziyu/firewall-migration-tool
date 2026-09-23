"""Cisco ASA configuration collection over SSH."""

from fwmigrate.extraction.sanitize import sanitize_raw_text

from .contracts import CollectedSource, CollectionError, SSH_FIELDS, validate_connection


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
        try:
            content = connection.send_command("show running-config", read_timeout=60)
        finally:
            connection.disconnect()
        if not content.strip():
            raise CollectionError("The device returned an empty configuration.")
        if len(content.encode("utf-8")) > 25_000_000:
            raise CollectionError("The device configuration exceeds the size limit.")
        return CollectedSource("cisco_asa", sanitize_raw_text(content), "live-cisco-asa.cfg", "ssh")


_collector = CiscoASACollector()
test_connection = _collector.test_connection
collect = _collector.collect
