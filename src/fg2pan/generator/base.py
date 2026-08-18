from abc import ABC, abstractmethod
from typing import List, Literal
from pydantic import BaseModel
from fg2pan.ir.core import IRConfig

class MigrationArtifact(BaseModel):
    filename: str
    content: str
    format: Literal["xml", "set", "terraform", "json", "txt"]

class BaseGenerator(ABC):
    @abstractmethod
    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        """Generate migration artifacts from the vendor-neutral IR."""
        pass
