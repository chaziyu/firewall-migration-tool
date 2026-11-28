"""Local loopback WSGI server with dual-stack binding and HTTP/1.1 keep-alive."""

from __future__ import annotations

import threading
from typing import Any

from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler, make_server


class KeepAliveWSGIRequestHandler(WSGIRequestHandler):
    """Serve local requests over HTTP/1.1 so browsers can reuse TCP connections."""

    protocol_version = "HTTP/1.1"


def _companion_loopback_host(host: str) -> str | None:
    if host in {"127.0.0.1", "localhost"}:
        return "::1"
    if host == "::1":
        return "127.0.0.1"
    return None


class LocalServer:
    """Manage a primary Werkzeug server and an optional loopback companion."""

    def __init__(
        self,
        primary: BaseWSGIServer,
        companion: BaseWSGIServer | None = None,
    ) -> None:
        self._primary = primary
        self._companion = companion
        self._lock = threading.Lock()
        self._closed = False

    @property
    def server_port(self) -> int:
        return self._primary.server_port

    def serve_forever(self) -> None:
        companion_thread: threading.Thread | None = None
        if self._companion is not None:
            companion_thread = threading.Thread(
                target=self._companion.serve_forever,
                daemon=True,
            )
            companion_thread.start()
        try:
            self._primary.serve_forever()
        finally:
            self.shutdown()
            if companion_thread is not None:
                companion_thread.join(timeout=2.0)

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for srv in (self._primary, self._companion):
            if srv is None:
                continue
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass


def create_local_server(
    app: Any,
    host: str = "127.0.0.1",
    port: int = 5000,
) -> LocalServer:
    """Bind a threaded HTTP/1.1 server on host plus its loopback family companion."""
    primary = make_server(
        host,
        port,
        app,
        threaded=True,
        request_handler=KeepAliveWSGIRequestHandler,
    )
    companion: BaseWSGIServer | None = None
    companion_host = _companion_loopback_host(host)
    if companion_host is not None:
        try:
            companion = make_server(
                companion_host,
                primary.server_port,
                app,
                threaded=True,
                request_handler=KeepAliveWSGIRequestHandler,
            )
        except OSError:
            companion = None
    return LocalServer(primary, companion)


def run_local_server(app: Any, host: str = "127.0.0.1", port: int = 5000) -> None:
    """Create and run the local HTTP/1.1 server until interrupted."""
    server = create_local_server(app, host=host, port=port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
