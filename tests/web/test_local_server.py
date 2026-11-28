"""Tests for the dual-stack HTTP/1.1 keep-alive local loopback server."""

from __future__ import annotations

import http.client
import threading

from fwmigrate.web import create_app
from fwmigrate.web_support.local_server import create_local_server


def test_local_server_serves_http11_on_ipv4_and_localhost(tmp_path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<div id='root'>ok</div>", encoding="utf-8")
    app = create_app({"TESTING": True, "WEB_MODE": "local", "FRONTEND_DIST_DIR": str(dist)})

    server = create_local_server(app, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        for host in ("127.0.0.1", "localhost"):
            conn = http.client.HTTPConnection(host, port, timeout=3)
            try:
                conn.request("GET", "/api/capabilities")
                resp = conn.getresponse()
                body = resp.read()
                assert resp.status == 200
                assert resp.version == 11
                assert b"live_device_access" in body
                # Second request reuses the keep-alive socket.
                conn.request("GET", "/")
                resp2 = conn.getresponse()
                assert resp2.status == 200
                assert b"ok" in resp2.read()
            finally:
                conn.close()

        if server._companion is not None:
            conn6 = http.client.HTTPConnection("::1", port, timeout=3)
            try:
                conn6.request("GET", "/api/capabilities")
                resp6 = conn6.getresponse()
                assert resp6.status == 200
                assert resp6.version == 11
                assert b"live_device_access" in resp6.read()
            finally:
                conn6.close()
    finally:
        server.shutdown()
        thread.join(timeout=3)
