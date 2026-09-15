import yaml
from pathlib import Path
from typing import Optional
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
            
    def load_profile(self, vendor_id: str, os_version: Optional[str] = None) -> VendorCapabilityProfile:
        """
        Loads the capability profile for a specific vendor and OS version.
        Falls back to 'default.yaml' if specific version is not found.
        """
        target_dir = self.capability_dir / vendor_id
        if not target_dir.exists():
            raise FileNotFoundError(f"No capability profiles found for vendor: {vendor_id}")
            
        default_file = target_dir / "default.yaml"
        version_file = target_dir / f"{os_version}.yaml" if os_version else None
        file_to_load = version_file if version_file and version_file.exists() else default_file
        
        if not file_to_load.exists():
            version_name = version_file.name if version_file else "a version profile"
            raise FileNotFoundError(f"Could not find {version_name} or default.yaml for {vendor_id}")
            
        with open(file_to_load, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            profile = VendorCapabilityProfile(**data)
            if profile.vendor_id != vendor_id:
                raise ValueError(
                    f"Capability profile vendor mismatch: expected {vendor_id}, "
                    f"got {profile.vendor_id}"
                )
            return profile
