import os
import sys
import shutil
import platform
import zipfile
import io
import re
import json
import subprocess
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, Callable
import requests


class TerraformBinaryManager:
    """
    Manages detection, version verification, and automatic self-healing downloads
    of the standalone HashiCorp Terraform CLI binary.
    """

    DEFAULT_VERSION = "1.9.5"

    def __init__(self, custom_bin_dir: Optional[Path] = None):
        if custom_bin_dir:
            self.bin_dir = Path(custom_bin_dir)
        elif getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            meipass_bin = Path(sys._MEIPASS) / "bin"
            if (meipass_bin / self.binary_name).exists():
                self.bin_dir = meipass_bin
            else:
                exe_bin = Path(sys.executable).parent / "bin"
                self.bin_dir = exe_bin
        else:
            # Default to <repo_root>/bin with fallback to user home directory
            repo_root = Path(__file__).resolve().parents[3]
            self.bin_dir = repo_root / "bin"

    @property
    def binary_name(self) -> str:
        return "terraform.exe" if platform.system().lower() == "windows" else "terraform"

    @property
    def local_binary_path(self) -> Path:
        return self.bin_dir / self.binary_name

    def get_platform_info(self) -> Tuple[str, str]:
        """Detect OS and Architecture mapped to HashiCorp release naming."""
        os_sys = platform.system().lower()
        if os_sys == "windows":
            os_name = "windows"
        elif os_sys == "darwin":
            os_name = "darwin"
        elif os_sys == "linux":
            os_name = "linux"
        else:
            os_name = os_sys

        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            arch = "amd64"
        elif machine in ("arm64", "aarch64"):
            arch = "arm64"
        elif machine in ("i386", "i686", "x86"):
            arch = "386"
        elif "arm" in machine:
            arch = "arm"
        else:
            arch = "amd64"

        return os_name, arch

    def find_binary(self) -> Optional[Path]:
        """
        Check for an existing Terraform binary in:
        1. System PATH via shutil.which()
        2. Local project bin directory
        """
        # 1. System PATH
        system_path = shutil.which("terraform")
        if system_path:
            p = Path(system_path)
            if p.exists():
                return p

        # 2. Local bin directory
        if self.local_binary_path.exists() and os.access(self.local_binary_path, os.X_OK | os.R_OK):
            return self.local_binary_path

        return None

    def get_or_download(
        self,
        version: str = DEFAULT_VERSION,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Path:
        """
        Locates an existing Terraform binary, or downloads it automatically if missing.
        """
        existing = self.find_binary()
        if existing:
            return existing

        return self.download_binary(version=version, progress_callback=progress_callback)

    def download_binary(
        self,
        version: str = DEFAULT_VERSION,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Path:
        """
        Downloads and extracts the Terraform binary for the current operating system and architecture.
        """
        os_name, arch = self.get_platform_info()
        url = f"https://releases.hashicorp.com/terraform/{version}/terraform_{version}_{os_name}_{arch}.zip"

        self.bin_dir.mkdir(parents=True, exist_ok=True)

        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get("content-length", 0))
            downloaded = 0
            zip_buffer = io.BytesIO()

            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    zip_buffer.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total_size > 0:
                        progress_callback(downloaded, total_size)

            zip_buffer.seek(0)
            with zipfile.ZipFile(zip_buffer) as zf:
                # Extract the binary
                for member in zf.namelist():
                    if member.lower() in ("terraform", "terraform.exe"):
                        extracted_path = zf.extract(member, self.bin_dir)
                        final_path = Path(extracted_path)
                        # Set execution permissions on POSIX
                        if os_name != "windows":
                            os.chmod(final_path, 0o755)
                        return final_path

            raise RuntimeError(f"Archive from {url} did not contain a terraform executable")

        except Exception as e:
            raise RuntimeError(f"Failed to download Terraform from {url}: {e}") from e

    def get_version(self, binary_path: Optional[Path] = None) -> Optional[str]:
        """
        Executes the binary with `version -json` or `version` and returns the version string.
        """
        target = binary_path or self.find_binary()
        if not target:
            return None

        try:
            proc = subprocess.run(
                [str(target), "version", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                return data.get("terraform_version")
        except Exception:
            pass

        # Fallback to plain text output
        try:
            proc = subprocess.run(
                [str(target), "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if proc.returncode == 0:
                match = re.search(r"Terraform v([\d\.]+)", proc.stdout)
                if match:
                    return match.group(1)
        except Exception:
            pass

        return None
