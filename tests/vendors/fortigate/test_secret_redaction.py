"""Regression tests for FortiGate secret redaction across sanitization, preview, and Excel exports."""

from __future__ import annotations

import io
import json
import re
import zipfile

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import ExcelExportProfile
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

_FAKE_ENC_BLOB_1 = "ENC " + ("A" * 44)
_FAKE_ENC_BLOB_2 = "ENC " + ("B" * 44)
_FAKE_ENC_BLOB_3 = "ENC " + ("C" * 44)

_SAMPLE_ADMIN_CONF = f"""#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system admin
    edit "secadmin"
        set accprofile "super_admin"
        set vdom "root"
        set password {_FAKE_ENC_BLOB_1}
        set history0 {_FAKE_ENC_BLOB_1}
        set history1 {_FAKE_ENC_BLOB_2}
        set custom-opaque-secret-like {_FAKE_ENC_BLOB_3}
    next
end
"""


def test_fortigate_history_and_enc_blobs_redacted_everywhere():
    sanitized = sanitize_source("fortigate", _SAMPLE_ADMIN_CONF)
    assert not re.search(r"\bENC\s+[A-Za-z0-9+/=]{16,}", sanitized)

    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(sanitized)

    preview = reporter.build_preview(analysis, include_source_commands=False)
    preview_json = json.dumps(preview)
    assert not re.search(r"\bENC\s+[A-Za-z0-9+/=]{16,}", preview_json)

    for profile in (ExcelExportProfile.FAST, ExcelExportProfile.FULL):
        buf = io.BytesIO()
        reporter.export_excel(analysis, buf, profile=profile, source_name="synthetic.conf")
        with zipfile.ZipFile(io.BytesIO(buf.getvalue()), "r") as zf:
            for member in zf.namelist():
                if member.endswith(".xml"):
                    xml_text = zf.read(member).decode("utf-8", errors="replace")
                    assert not re.search(r"\bENC\s+[A-Za-z0-9+/=]{16,}", xml_text), (
                        f"Unredacted ENC blob found in {profile.value} Excel member {member}"
                    )
