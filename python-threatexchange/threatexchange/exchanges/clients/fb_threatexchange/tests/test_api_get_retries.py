# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Tests that GETs to the ThreatExchange API get timeouts and retries.

These run the real requests/urllib3 stack against a throwaway local server.
"""

import json
import threading
import typing as t
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests

from threatexchange.exchanges.clients.fb_threatexchange import api as api_module
from threatexchange.exchanges.clients.fb_threatexchange.api import ThreatExchangeAPI

_THROTTLED = (400, {"error": {"message": "(#4) limit", "code": 4}})
_BAD_TOKEN = (400, {"error": {"message": "bad token", "code": 190}})
_OK = (200, {"data": [{"id": "1"}]})
_SERVER_ERROR = (500, {"error": {"message": "oops", "code": 2}})


class _Server:
    """Replies with the scripted responses in order, then repeats the last."""

    def __init__(self, script: t.List[t.Tuple[int, dict]]) -> None:
        self.script = script
        self.requests: t.List[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                i = min(len(outer.requests), len(outer.script) - 1)
                outer.requests.append(self.path)
                status, body = outer.script[i]
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args: t.Any) -> None:
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/v99.0"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> t.List[float]:
    """Record (and skip) every backoff sleep, from us and from urllib3"""
    slept: t.List[float] = []
    monkeypatch.setattr("time.sleep", slept.append)
    return slept


@pytest.fixture
def serve() -> t.Iterator[t.Callable[..., t.Tuple[_Server, ThreatExchangeAPI]]]:
    servers: t.List[_Server] = []

    def start(*script: t.Tuple[int, dict]) -> t.Tuple[_Server, ThreatExchangeAPI]:
        server = _Server(list(script))
        servers.append(server)
        return server, ThreatExchangeAPI("123|token", endpoint_override=server.base_url)

    yield start
    for server in servers:
        server.close()


def test_get_uses_session_with_timeout_and_retries():
    """Regression: get_json_from_url used to bypass the session with requests.get"""
    api = ThreatExchangeAPI("123|token")
    with api._get_session() as session:
        for url in (
            "https://graph.facebook.com/v99.0/1/threat_updates/",
            # paging.next can be a different path than the base URL
            "https://graph.facebook.com/other/path",
        ):
            adapter = session.get_adapter(url)
            assert adapter.timeout == 60
            assert adapter.max_retries.total == 5
            assert 500 in adapter.max_retries.status_forcelist


def test_success_needs_one_request(serve, sleeps):
    server, api = serve(_OK)
    assert api.get_json_from_url(f"{api._base_url}/x") == _OK[1]
    assert len(server.requests) == 1
    assert sleeps == []


def test_server_errors_are_retried(serve, sleeps):
    server, api = serve(_SERVER_ERROR, _SERVER_ERROR, _OK)
    assert api.get_json_from_url(f"{api._base_url}/x") == _OK[1]
    assert len(server.requests) == 3


def test_persistent_server_error_raises_http_error(serve, sleeps):
    server, api = serve(_SERVER_ERROR)
    with pytest.raises(requests.HTTPError) as e:
        api.get_json_from_url(f"{api._base_url}/x")
    assert e.value.response.status_code == 500
    assert len(server.requests) == 6  # 1 + 5 retries


def test_throttling_waits_then_retries(serve, sleeps):
    server, api = serve(_THROTTLED, _THROTTLED, _OK)
    assert api.get_json_from_url(f"{api._base_url}/x") == _OK[1]
    assert len(server.requests) == 3
    assert sleeps == [15, 30]


def test_persistent_throttling_gives_up(serve, sleeps):
    server, api = serve(_THROTTLED)
    with pytest.raises(requests.HTTPError) as e:
        api.get_json_from_url(f"{api._base_url}/x")
    assert e.value.response.json()["error"]["code"] == 4
    assert sleeps == list(api_module._THROTTLE_BACKOFF_SEC)
    assert len(server.requests) == len(api_module._THROTTLE_BACKOFF_SEC) + 1


def test_other_client_errors_are_not_retried(serve, sleeps):
    server, api = serve(_BAD_TOKEN)
    with pytest.raises(requests.HTTPError):
        api.get_json_from_url(f"{api._base_url}/x")
    assert len(server.requests) == 1
    assert sleeps == []


def test_params_are_sent(serve, sleeps):
    server, api = serve(_OK)
    api.get_json_from_url(f"{api._base_url}/x", {"limit": 5})
    assert server.requests == ["/v99.0/x?limit=5"]
