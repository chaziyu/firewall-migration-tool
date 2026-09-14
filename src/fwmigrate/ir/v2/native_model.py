from pydantic import BaseModel, ConfigDict
from typing import Dict, Any

class NativeModel(BaseModel):
    """
    Base class for vendor-specific native configurations.
    All vendors must map their raw JSON/dict to a subclass of this.
    """
    model_config = ConfigDict(extra='allow')
    
    # Store raw fields that couldn't be cleanly parsed or are unsupported
    _unparsed_raw: Dict[str, Any] = {}
    
    def set_unparsed(self, key: str, value: Any):
        self._unparsed_raw[key] = value
        
    def get_unparsed(self) -> Dict[str, Any]:
        return self._unparsed_raw
