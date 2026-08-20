from typing import Dict, Any, List, Optional
from pydantic import BaseModel
import time

class Identity(BaseModel):
    """
    Represents an authenticated user identity independent of the authentication mechanism.
    """
    user_id: str
    email: str
    name: str
    claims: Dict[str, Any]
    roles: List[str]
    is_authenticated: bool

class BaseOIDCProvider:
    """
    Abstract base class for OIDC token verification.
    """
    def verify_token(self, token: str) -> Optional[Identity]:
        raise NotImplementedError("Subclasses must implement verify_token")

class DevOIDCProvider(BaseOIDCProvider):
    """
    A stub provider for development that allows testing without a real IdP.
    WARNING: Not for production use.
    """
    def verify_token(self, token: str) -> Optional[Identity]:
        # For dev purposes, token could be "dev-token:role1,role2"
        if not token.startswith("dev-token"):
            return None
            
        parts = token.split(":")
        roles = parts[1].split(",") if len(parts) > 1 else ["VIEWER"]
        
        return Identity(
            user_id="dev-user-123",
            email="dev@example.com",
            name="Developer",
            claims={"iss": "dev-issuer", "exp": int(time.time()) + 3600},
            roles=roles,
            is_authenticated=True
        )

# Factory or DI can configure the real provider (e.g. Entra ID) later.
def get_oidc_provider() -> BaseOIDCProvider:
    # Later: if env == "prod", return EntraIDOIDCProvider()
    return DevOIDCProvider()
