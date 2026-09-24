"""Proves the retry adapter actually works — over a REAL local HTTP server,
real sockets, no requests_mock involved.

requests_mock cannot be used for this: it patches the transport at a level
that bypasses any adapter WE mounted (confirmed directly — see
test_client_transport.py's two failing assertions before this file existed).
So the only honest way to verify "honour Retry-After exactly" and "retry on
429/5xx" — the whole reason this module doesn't depend on the vmray-rest-api
vendor SDK — is to exercise the real urllib3.Retry object end to end.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from vmray_modules.client import BadResponseError, VMRayClient


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Serves a scripted sequence of (status_code, headers, body) responses,
    one per request, repeating the last once exhausted."""

    script: ClassVar[list[tuple[int, dict[str, str], dict]]] = []
    request_times: ClassVar[list[float]] = []

    def do_GET(self):
        _ScriptedHandler.request_times.append(time.monotonic())
        index = min(len(_ScriptedHandler.request_times) - 1, len(_ScriptedHandler.script) - 1)
        status, headers, body = _ScriptedHandler.script[index]

        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence default request logging
        pass


@pytest.fixture
def scripted_server():
    _ScriptedHandler.script = []
    _ScriptedHandler.request_times = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ScriptedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{server.server_port}"

    server.shutdown()
    server.server_close()


@pytest.mark.slow
def test_5xx_is_actually_retried_over_real_sockets(scripted_server):
    base_url = scripted_server
    _ScriptedHandler.script = [
        (500, {}, {"error_msg": "boom"}),
        (500, {}, {"error_msg": "boom"}),
        (200, {}, {"result": "ok", "data": {"version": "2026.2.1"}}),
    ]
    client = VMRayClient(base_url=base_url, api_key="x")

    result = client.system_info()

    assert result == {"version": "2026.2.1"}
    assert len(_ScriptedHandler.request_times) == 3  # two real failures, genuinely retried


@pytest.mark.slow
def test_retry_exhaustion_over_real_sockets_eventually_raises(scripted_server):
    base_url = scripted_server
    _ScriptedHandler.script = [(503, {}, {"error_msg": "down"})]
    client = VMRayClient(base_url=base_url, api_key="x")

    with pytest.raises(BadResponseError):
        client.system_info()

    # total=5 in the mounted Retry -> 1 initial attempt + 5 retries = 6
    assert len(_ScriptedHandler.request_times) == 6


@pytest.mark.slow
def test_429_retry_after_is_actually_honoured(scripted_server):
    """The entire point of hand-rolling this client over the vendor SDK:
    urllib3's respect_retry_after_header must make the real wait between
    attempt 1 and attempt 2 track the server's stated Retry-After value."""
    base_url = scripted_server
    _ScriptedHandler.script = [
        (429, {"Retry-After": "1"}, {"error_msg": "throttled"}),
        (200, {}, {"result": "ok", "data": {"version": "2026.2.1"}}),
    ]
    client = VMRayClient(base_url=base_url, api_key="x")

    result = client.system_info()

    assert result == {"version": "2026.2.1"}
    assert len(_ScriptedHandler.request_times) == 2
    gap = _ScriptedHandler.request_times[1] - _ScriptedHandler.request_times[0]
    assert gap >= 0.9  # honoured the 1-second Retry-After, not a faster default backoff
