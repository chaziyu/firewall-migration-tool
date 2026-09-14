from fwmigrate.ir.v2.models import IRConfigV2
from fwmigrate.ir.v2.native_model import NativeModel
from fwmigrate.ir.v2.provenance import FieldStatus

class Normalizer:
    """
    Base class for transforming a NativeModel into IRConfigV2.
    """
    
    def normalize(self, native_model: NativeModel) -> IRConfigV2:
        raise NotImplementedError("Subclasses must implement normalize")
        
    def determine_status(self, original_field_exists: bool, ir_field_mapped: bool, is_supported: bool = True) -> FieldStatus:
        if not original_field_exists:
            return FieldStatus.IGNORED # Irrelevant
        if not is_supported:
            return FieldStatus.UNSUPPORTED
        if ir_field_mapped:
            return FieldStatus.FULL
        return FieldStatus.PARTIAL
