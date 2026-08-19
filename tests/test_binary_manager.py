import os
import io
import zipfile
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from fwmigrate.engine.binary_manager import TerraformBinaryManager


def test_platform_info():
    mgr = TerraformBinaryManager()
    os_name, arch = mgr.get_platform_info()
    assert os_name in ("windows", "darwin", "linux")
    assert arch in ("amd64", "arm64", "386", "arm")


def test_find_binary_path(tmp_path):
    mgr = TerraformBinaryManager(custom_bin_dir=tmp_path)
    fake_bin = tmp_path / mgr.binary_name
    fake_bin.write_text("echo fake terraform")
    os.chmod(fake_bin, 0o755)

    found = mgr.find_binary()
    assert found == fake_bin


def test_download_binary_mocked(tmp_path):
    mgr = TerraformBinaryManager(custom_bin_dir=tmp_path)
    
    # Create fake zip archive in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr(mgr.binary_name, "mock terraform content")
    zip_bytes = zip_buffer.getvalue()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-length": str(len(zip_bytes))}
    mock_resp.iter_content = lambda chunk_size: [zip_bytes]

    with patch("requests.get", return_value=mock_resp):
        downloaded = mgr.download_binary(version="1.9.5")
        assert downloaded.exists()
        assert downloaded.name == mgr.binary_name
        assert downloaded.read_text() == "mock terraform content"


def test_get_version_json():
    mgr = TerraformBinaryManager()
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = '{"terraform_version": "1.9.5", "platform": "windows_amd64"}'

    with patch("subprocess.run", return_value=fake_proc):
        version = mgr.get_version(Path("fake_terraform"))
        assert version == "1.9.5"
