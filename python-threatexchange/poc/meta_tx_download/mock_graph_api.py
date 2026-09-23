# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
A local stand-in for Meta's ThreatExchange Graph API /threat_updates endpoint.

It implements the parts of the contract the `tx` CLI relies on:
  * GET /<version>/<privacy_group>/threat_updates/
  * start_time (inclusive), stop_time (exclusive), limit, types, fields
  * results ordered by last_updated
  * cursor pagination via paging.next (a full URL, params included)

and adds knobs the real API doesn't expose, so we can study client behavior:
  * a latency model: base_ms + per_record_ms * records_in_page
    (per_record_ms is only charged when nested `descriptors{...}` are requested)
  * --max-rps: app-wide request rate limit, answered with Graph error code 4
  * --max-concurrent: server-side concurrency cap (extra requests queue)
  * --fail-every N: every Nth request returns HTTP 500
  * --hang-at N: the Nth request stalls for --hang-sec seconds

The latency model is an ASSUMPTION calibrated to Meta's own documentation
("~200,000 records an hour" when resolving nested fields), NOT a measurement of
Meta's servers. See REPORT.md.
"""

import argparse
import bisect
import json
import sys
import threading
import time
import typing as t
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import synthetic_data


@dataclass
class MockConfig:
    base_ms: float = 150.0
    per_record_ms: float = 18.0  # 200K records/hr/serial-stream => 18ms/record
    per_record_light_ms: float = 0.2
    max_limit: int = 1000
    max_rps: float = 0.0  # 0 = unlimited
    max_concurrent: int = 0  # 0 = unlimited
    fail_every: int = 0
    hang_at: t.Set[int] = field(default_factory=set)
    hang_sec: float = 3600.0
    time_scale: float = 1.0  # multiply all sleeps (for fast benchmarks)


class MockState:
    def __init__(self, records: t.List[dict], config: MockConfig) -> None:
        self.records = records
        self.times = [r["last_updated"] for r in records]
        self.config = config
        self.lock = threading.Lock()
        self.request_count = 0
        self.throttled_count = 0
        self.failed_count = 0
        self.records_served = 0
        self._window: t.List[float] = []
        self._sem = (
            threading.BoundedSemaphore(config.max_concurrent)
            if config.max_concurrent
            else None
        )
        self._type_views: t.Dict[t.Tuple[str, ...], t.Tuple[list, list]] = {}

    def view(self, types: t.Tuple[str, ...]) -> t.Tuple[list, list]:
        if not types:
            return self.records, self.times
        with self.lock:
            if types not in self._type_views:
                recs = [r for r in self.records if r["type"] in types]
                self._type_views[types] = (recs, [r["last_updated"] for r in recs])
            return self._type_views[types]

    def admit(self) -> t.Tuple[int, bool]:
        """Returns (request_number, throttled)"""
        now = time.monotonic()
        with self.lock:
            self.request_count += 1
            n = self.request_count
            if self.config.max_rps:
                cutoff = now - 1.0
                self._window = [x for x in self._window if x > cutoff]
                if len(self._window) >= self.config.max_rps:
                    self.throttled_count += 1
                    return n, True
                self._window.append(now)
            return n, False


def _project(rec: dict, want_descriptors: bool) -> dict:
    if want_descriptors or "descriptors" not in rec:
        return rec
    return {k: v for k, v in rec.items() if k != "descriptors"}


class Handler(BaseHTTPRequestHandler):
    state: MockState  # set by make_server
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: t.Any) -> None:  # silence
        pass

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        st = self.state
        cfg = st.config
        url = urllib.parse.urlparse(self.path)
        if url.path == "/__stats":
            self._send(
                200,
                {
                    "requests": st.request_count,
                    "throttled": st.throttled_count,
                    "failed": st.failed_count,
                    "records_served": st.records_served,
                },
            )
            return
        parts = [p for p in url.path.split("/") if p]
        if len(parts) != 3 or parts[2] != "threat_updates":
            self._send(404, {"error": {"message": "unknown path", "code": 803}})
            return
        q = dict(urllib.parse.parse_qsl(url.query))
        if "access_token" not in q:
            self._send(400, {"error": {"message": "no token", "code": 190}})
            return

        n, throttled = st.admit()
        if throttled:
            # Graph API style throttle. The exact HTTP status Meta uses for
            # ThreatExchange throttling is unverified; 400 + code 4 is typical.
            self._send(
                400,
                {
                    "error": {
                        "message": "(#4) Application request limit reached",
                        "type": "OAuthException",
                        "code": 4,
                    }
                },
            )
            return
        if n in cfg.hang_at:
            time.sleep(cfg.hang_sec)
        if cfg.fail_every and n % cfg.fail_every == 0:
            with st.lock:
                st.failed_count += 1
            self._send(500, {"error": {"message": "internal error", "code": 1}})
            return

        types = tuple(sorted(filter(None, q.get("types", "").split(","))))
        recs, times = st.view(types)
        start = int(q["start_time"]) if q.get("start_time") else 0
        stop = int(q["stop_time"]) if q.get("stop_time") else None
        limit = min(int(q.get("limit") or 25), cfg.max_limit)
        lo = bisect.bisect_left(times, start)
        hi = bisect.bisect_left(times, stop) if stop is not None else len(times)
        offset = lo + int(q.get("after", 0))
        page = recs[offset : min(offset + limit, hi)]
        want_desc = "descriptors" in q.get("fields", "")

        cost_ms = cfg.base_ms + len(page) * (
            cfg.per_record_ms if want_desc else cfg.per_record_light_ms
        )
        if st._sem:
            st._sem.acquire()
        try:
            time.sleep(cost_ms / 1000.0 * cfg.time_scale)
        finally:
            if st._sem:
                st._sem.release()

        body: t.Dict[str, t.Any] = {"data": [_project(r, want_desc) for r in page]}
        if offset + len(page) < hi:
            nq = dict(q)
            nq["after"] = str(offset + len(page) - lo)
            host = self.headers.get("Host")
            body["paging"] = {
                "cursors": {"after": nq["after"]},
                "next": f"http://{host}{url.path}?{urllib.parse.urlencode(nq)}",
            }
        with st.lock:
            st.records_served += len(page)
        self._send(200, body)


def make_server(
    records: t.List[dict], config: MockConfig, port: int = 0
) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"state": MockState(records, config)})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--records", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--base-ms", type=float, default=150.0)
    ap.add_argument("--per-record-ms", type=float, default=18.0)
    ap.add_argument("--max-limit", type=int, default=1000)
    ap.add_argument("--max-rps", type=float, default=0.0)
    ap.add_argument("--max-concurrent", type=int, default=0)
    ap.add_argument("--fail-every", type=int, default=0)
    ap.add_argument("--hang-at", type=int, nargs="*", default=[])
    ap.add_argument("--hang-sec", type=float, default=3600.0)
    ap.add_argument("--time-scale", type=float, default=1.0)
    a = ap.parse_args()
    cfg = MockConfig(
        base_ms=a.base_ms,
        per_record_ms=a.per_record_ms,
        max_limit=a.max_limit,
        max_rps=a.max_rps,
        max_concurrent=a.max_concurrent,
        fail_every=a.fail_every,
        hang_at=set(a.hang_at),
        hang_sec=a.hang_sec,
        time_scale=a.time_scale,
    )
    server = make_server(synthetic_data.generate(a.records, a.seed), cfg, a.port)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
