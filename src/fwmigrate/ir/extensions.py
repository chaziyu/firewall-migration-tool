from pydantic import BaseModel, ConfigDict, Field

from .policy import IRFortiGateSourceRule


class _VendorExtension(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IRFortiOSExtensions(_VendorExtension):
    security_policies: list[IRFortiGateSourceRule] = Field(default_factory=list)


class IRPANOSExtensions(_VendorExtension):
    pass


class IRCheckPointExtensions(_VendorExtension):
    pass


class IRCiscoASAExtensions(_VendorExtension):
    pass


class IRCiscoFTDExtensions(_VendorExtension):
    pass


class IRJunosExtensions(_VendorExtension):
    pass


class IRVendorExtensions(BaseModel):
    fortios: IRFortiOSExtensions = Field(default_factory=IRFortiOSExtensions)
    panos: IRPANOSExtensions = Field(default_factory=IRPANOSExtensions)
    checkpoint: IRCheckPointExtensions = Field(default_factory=IRCheckPointExtensions)
    cisco_asa: IRCiscoASAExtensions = Field(default_factory=IRCiscoASAExtensions)
    cisco_ftd: IRCiscoFTDExtensions = Field(default_factory=IRCiscoFTDExtensions)
    junos: IRJunosExtensions = Field(default_factory=IRJunosExtensions)


__all__ = [
    "IRFortiOSExtensions",
    "IRPANOSExtensions",
    "IRCheckPointExtensions",
    "IRCiscoASAExtensions",
    "IRCiscoFTDExtensions",
    "IRJunosExtensions",
    "IRVendorExtensions",
]
