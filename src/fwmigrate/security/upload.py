import os
import uuid
import tempfile
from pathlib import Path
from werkzeug.utils import secure_filename
from typing import Optional

class UploadSecurityViolation(Exception):
    pass

class UploadSecurityPolicy:
    """
    Validates uploaded configuration files to prevent abuse, path traversal, and huge files.
    """
    
    def __init__(self, max_size_bytes: int = 10 * 1024 * 1024, allowed_extensions: set[str] = None):
        self.max_size_bytes = max_size_bytes
        self.allowed_extensions = allowed_extensions or {'.conf', '.txt', '.json', '.xml', '.yaml', '.yml'}

    def validate_file(self, file_storage) -> Path:
        """
        Validates the uploaded file from a Flask FileStorage object.
        Returns a Path to a safe temporary file if successful.
        """
        if not file_storage or not file_storage.filename:
            raise UploadSecurityViolation("No file provided.")
            
        filename = secure_filename(file_storage.filename)
        ext = Path(filename).suffix.lower()
        if ext not in self.allowed_extensions:
            raise UploadSecurityViolation(f"File extension '{ext}' is not allowed.")
            
        # Isolate in a temp directory with a randomized name
        temp_dir = Path(tempfile.gettempdir()) / "fwmigrate_uploads" / str(uuid.uuid4())
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        safe_path = temp_dir / filename
        file_storage.save(str(safe_path))
        
        # Check size after saving (or ideally during stream, but this is a simpler first pass)
        size = safe_path.stat().st_size
        if size > self.max_size_bytes:
            safe_path.unlink()
            raise UploadSecurityViolation(f"File size exceeds limit of {self.max_size_bytes} bytes.")
            
        return safe_path
        
    def is_safe_filename(self, filename: str) -> bool:
        if ".." in filename or "/" in filename or "\\" in filename:
            return False
        ext = Path(filename).suffix.lower()
        if ext not in self.allowed_extensions:
            return False
        return True
        
    def is_safe_content(self, content: bytes) -> bool:
        if content.startswith(b"\x7FELF"):
            return False
        return True
