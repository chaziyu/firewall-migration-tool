import os
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class SecretManager:
    """
    Abstracts retrieval of secrets to prevent them from being hardcoded or written to disk.
    In enterprise mode, this should integrate with a Vault.
    For local/desktop mode, it leverages the OS keystore or environment variables.
    """
    
    def get_secret(self, key: str) -> Optional[str]:
        """
        Retrieves a secret by its key.
        """
        raise NotImplementedError("Subclasses must implement get_secret")


class DevEnvironmentSecretManager(SecretManager):
    """
    Temporary development fallback that reads from environment variables.
    WARNING: DEV ONLY. Do not use in production.
    """
    
    def __init__(self):
        logger.warning("DEV ONLY: Using DevEnvironmentSecretManager. Secrets may leak into environment.")
        
    def get_secret(self, key: str) -> Optional[str]:
        return os.environ.get(key)


class EphemeralCredentialMaterializer:
    """
    Handles materializing credentials securely into memory for the duration of a worker execution,
    ensuring they are never written to long-lived files like terraform.tfvars.
    """
    
    def __init__(self, secret_manager: SecretManager):
        self.secret_manager = secret_manager
        
    def get_credentials(self, keys: list[str]) -> Dict[str, str]:
        """
        Fetches multiple credentials securely.
        """
        creds = {}
        for k in keys:
            val = self.secret_manager.get_secret(k)
            if val is not None:
                creds[k] = val
        return creds

def get_secret_manager() -> SecretManager:
    # Eventually hook into Enterprise Vault based on configuration
    return DevEnvironmentSecretManager()
