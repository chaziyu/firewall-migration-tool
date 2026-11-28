import io
import time
import zipfile
from pathlib import Path

from fwmigrate.web import create_app


def _make_tsf_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_capabilities_exposes_tsf_limits():
    public_client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    pub_caps = public_client.get("/api/capabilities").json
    assert pub_caps["tsf_enabled"] is True
    assert pub_caps["tsf_max_zip_mb"] == 100

    local_client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    loc_caps = local_client.get("/api/capabilities").json
    assert loc_caps["tsf_enabled"] is True
    assert loc_caps["tsf_max_zip_mb"] == 500


def test_tsf_api_end_to_end_lifecycle(tmp_path: Path):
    app = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "TSF_SESSIONS_DIR": str(tmp_path),
    })
    client = app.test_client()

    lines = "\n".join(
        f"line {i}: tunnel 192.0.2.10 down" if i == 510 else f"line {i}: ok"
        for i in range(1, 520)
    )
    zip_bytes = _make_tsf_zip({
        "var/log/pan/mp-log.log": lines.encode("utf-8"),
        "opt/pancfg/running-config.xml": b"<config><hostname>PA-VM</hostname></config>",
        "var/log/raw.png": b"\x89PNG\r\n\x1a\n",
    })

    upload_resp = client.post(
        "/api/tsf/upload",
        data={"file": (io.BytesIO(zip_bytes), "techsupport.zip")},
        content_type="multipart/form-data",
    )
    assert upload_resp.status_code == 202
    job_id = upload_resp.json["job_id"]

    session_id = ""
    deadline = time.time() + 5.0
    while time.time() < deadline:
        prog = client.get(f"/api/tsf/progress/{job_id}").json
        if prog["status"] == "done":
            session_id = prog["session_id"]
            assert prog["total_files"] == 3
            break
        assert prog["status"] != "error", prog
        time.sleep(0.02)
    assert session_id

    # Wait for content index completion
    deadline = time.time() + 5.0
    while time.time() < deadline:
        status = client.get(f"/api/tsf/status?session_id={session_id}").json
        if status["content_ready"]:
            break
        time.sleep(0.02)
    assert status["content_ready"] is True
    assert status["total_files"] == 3

    tree = client.get(f"/api/tsf/tree?session_id={session_id}&path=").json
    assert tree["dirs"] == ["opt", "var"]

    fn_search = client.get(f"/api/tsf/search?session_id={session_id}&mode=filename&q=running-config").json
    assert fn_search["results"][0]["rel_path"] == "opt/pancfg/running-config.xml"

    content_search = client.get(f"/api/tsf/search?session_id={session_id}&mode=content&q=192.0.2.10").json
    assert len(content_search["results"]) == 1
    assert content_search["results"][0]["line_number"] == 510

    file_view = client.get(
        f"/api/tsf/file?session_id={session_id}&path=var/log/pan/mp-log.log&jump_line=510"
    ).json
    assert file_view["success"] is True
    assert file_view["page"] == 1
    assert file_view["total_pages"] == 2
    assert any(ln == 510 for ln, _ in file_view["lines"])

    bin_view = client.get(f"/api/tsf/file?session_id={session_id}&path=var/log/raw.png").json
    assert bin_view["success"] is False
    assert bin_view["is_binary"] is True

    dl = client.get(f"/api/tsf/download?session_id={session_id}&path=opt/pancfg/running-config.xml")
    assert dl.status_code == 200
    assert b"<hostname>PA-VM</hostname>" in dl.data
    dl.close()

    deleted = client.delete(f"/api/tsf/session/{session_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/tsf/status?session_id={session_id}").status_code == 404


def test_tsf_upload_validation_and_invalid_session(tmp_path: Path):
    client = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "TSF_SESSIONS_DIR": str(tmp_path),
    }).test_client()

    non_zip = client.post(
        "/api/tsf/upload",
        data={"file": (io.BytesIO(b"hello"), "config.xml")},
        content_type="multipart/form-data",
    )
    assert non_zip.status_code == 400

    assert client.get("/api/tsf/status?session_id=../bad").status_code == 400
    assert client.get("/api/tsf/progress/invalid").status_code == 400
    assert client.get("/api/tsf/progress/" + ("0" * 32)).status_code == 404
