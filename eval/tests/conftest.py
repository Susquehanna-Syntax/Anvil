"""Shared fixtures: a local HTTP server standing in for every remote the harness talks to."""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Callable, Iterator

import pytest

Handler = Callable[[str, str, bytes | None], tuple[int, bytes, str]]


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


@pytest.fixture
def http_stub() -> Iterator[Callable[[Handler], str]]:
    """Start a server whose responses come from ``handler(method, path, body)``; yield its URL."""
    servers: list[_Server] = []

    def start(handler: Handler) -> str:
        class H(http.server.BaseHTTPRequestHandler):
            def _serve(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                status, payload, ctype = handler(method, self.path, body)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:  # noqa: N802
                self._serve("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._serve("POST")

            def log_message(self, *args) -> None:
                pass

        srv = _Server(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def json_response(obj, status: int = 200) -> tuple[int, bytes, str]:
    return status, json.dumps(obj).encode(), "application/json"
