"""FortiOS 7.4.6 multi-value ``system dns server-hostname`` model."""

from typing import List

from pydantic import Field

from fwmigrate.parsers.fortigate.model import FGDns


class FGDnsMultiValue746(FGDns):
    """FortiGate DNS source model with ordered server hostnames."""

    server_hostname: List[str] = Field(default_factory=list)
