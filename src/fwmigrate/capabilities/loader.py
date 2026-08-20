import yaml
from pathlib import Path
from fwmigrate.capabilities.schema import VendorCapabilityProfile

class CapabilityLoader:
    """
    Loads VendorCapabilityProfile objects from YAML definitions.
    """
    
    def __init__(self, capability_dir: Path = None):
        if not capability_dir:
            self.capability_dir = Path(__file__).parent / "profiles"
        else:
            self.capability_dir = capability_dir
            
    def load_profile(self, vendor_id: str, os_version: str) -> VendorCapabilityProfile:
        """
        Loads the capability profile for a specific vendor and OS version.
        Falls back to 'default.yaml' if specific version is not found.
        """
        target_dir = self.capability_dir / vendor_id
        if not target_dir.exists():
            raise FileNotFoundError(f"No capability profiles found for vendor: {vendor_id}")
            
        version_file = target_dir / f"{os_version}.yaml"
        default_file = target_dir / "default.yaml"
        
        file_to_load = version_file if version_file.exists() else default_file
        
        if not file_to_load.exists():
            raise FileNotFoundError(f"Could not find {version_file.name} or default.yaml for {vendor_id}")
            
        with open(file_to_load, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return VendorCapabilityProfile(**data)
