# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Benchmark stock vs parallel /threat_updates download against the mock server.

    python poc/meta_tx_download/bench_fetch.py [--records 20000] [--scale 0.02]

The mock runs in a subprocess (so its JSON encoding doesn't share our GIL) with
all server-side sleeps multiplied by --scale. "real-equiv" columns divide the
measured wall time by --scale, i.e. they assume client CPU is negligible
(bench_client_cpu below measures that assumption).

Every number here is a property of the MOCK's latency model, which is an
assumption. What the benchmark can legitimately show:
  * the parallel client's mechanics scale (no client-side bottleneck)
  * how much time-skewed data hurts naive sharding
  * that a server-side throughput cap sets the ceiling, not the worker count
It cannot tell you how Meta's servers behave under concurrent load.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import typing as t

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import synthetic_data  # noqa: E402
from parallel_fetch import (  # noqa: E402
    ParallelFBThreatExchangeSignalExchangeAPI,
    RetryingGraphClient,
)
from threatexchange.exchanges.clients.fb_threatexchange.api import (  # noqa: E402
    ThreatExchangeAPI,
)
from threatexchange.exchanges.impl.fb_threatexchange_api import (  # noqa: E402
    FBThreatExchangeCollabConfig,
    FBThreatExchangeIndicatorRecord,
    FBThreatExchangeSignalExchangeAPI,
)
from threatexchange.exchanges.clients.fb_threatexchange.threat_updates import (  # noqa: E402
    ThreatUpdateJSON,
)
from threatexchange.cli.main import _DEFAULT_SIGNAL_TYPES  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = f"{synthetic_data.MY_APP_ID}|abcdefghijklmnopqrstuvwxyz"
COLLAB = FBThreatExchangeCollabConfig(name="bench", privacy_group=1234567890)


class Mock:
    def __init__(self, records: int, scale: float, *extra: str) -> None:
        self.proc = subprocess.Popen(
            [
                sys.executable,
                os.path.join(HERE, "mock_graph_api.py"),
                "--records",
                str(records),
                "--time-scale",
                str(scale),
                *extra,
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.proc.stdout
        port = int(self.proc.stdout.readline())
        self.base = f"http://127.0.0.1:{port}/v21.0"

    def stats(self) -> dict:
        import requests

        return requests.get(self.base.rsplit("/", 1)[0] + "/__stats").json()

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait()


def run(api, signal_types=()) -> t.Tuple[float, int, int]:
    state: dict = {}
    fetched = 0
    t0 = time.monotonic()
    for d in api.fetch_iter(list(signal_types), None):
        fetched += len(d.updates)
        FBThreatExchangeSignalExchangeAPI.naive_fetch_merge(state, d.updates)
    return time.monotonic() - t0, fetched, len(state)


def stock(base: str) -> FBThreatExchangeSignalExchangeAPI:
    return FBThreatExchangeSignalExchangeAPI(
        ThreatExchangeAPI(TOKEN, endpoint_override=base), COLLAB
    )


def parallel(base: str, workers: int, spw: int, page: int, **kw):
    api = ParallelFBThreatExchangeSignalExchangeAPI(
        ThreatExchangeAPI(TOKEN, endpoint_override=base), COLLAB
    )
    api.workers, api.shards_per_worker, api.page_size = workers, spw, page
    for k, v in kw.items():
        setattr(api, k, v)
    api.graph = RetryingGraphClient(pool_size=workers, backoff_base=0.05)
    return api


def bench_client_cpu(n: int = 20000) -> float:
    """Measured client-side CPU per record: JSON decode + record conversion."""
    recs = synthetic_data.generate(n, seed=99)
    raw = json.dumps({"data": recs})
    t0 = time.process_time()
    data = json.loads(raw)["data"]
    for r in data:
        FBThreatExchangeIndicatorRecord.from_threatexchange_json(
            synthetic_data.MY_APP_ID, ThreatUpdateJSON(r)
        )
    return (time.process_time() - t0) / n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=20000)
    ap.add_argument("--scale", type=float, default=0.02)
    ap.add_argument("--out", default=os.path.join(HERE, "results", "fetch.json"))
    a = ap.parse_args()
    N, S = a.records, a.scale
    rows: t.List[dict] = []

    def record(scenario: str, label: str, secs: float, fetched: int, live: int):
        base = rows[0]["secs"] if rows else secs
        row = {
            "scenario": scenario,
            "config": label,
            "secs": round(secs, 2),
            "speedup_vs_stock": round(base / secs, 2),
            "real_equiv_hours_for_1.4M": round(secs / S / 3600 * 1_400_000 / N, 2),
            "records_fetched": fetched,
            "live_records": live,
        }
        rows.append(row)
        print(json.dumps(row), flush=True)

    cpu = bench_client_cpu()
    print(f"client CPU per record: {cpu*1e6:.1f} us", flush=True)

    # 1. Baseline + page size + parallelism, per-record-dominated cost model
    m = Mock(N, S)
    try:
        secs, f, live = run(stock(m.base))
        record("A: default model", "stock serial, page=100", secs, f, live)
        expected_live = live
        for page in (500, 1000):
            secs, f, live = run(parallel(m.base, 1, 1, page))
            assert live == expected_live
            record("A: default model", f"1 worker, page={page}", secs, f, live)
        for w in (2, 4, 8, 16, 32):
            secs, f, live = run(parallel(m.base, w, 8, 500))
            assert live == expected_live
            record(
                "A: default model", f"{w} workers x8 shards, page=500", secs, f, live
            )
        secs, f, live = run(parallel(m.base, 16, 1, 500))
        assert live == expected_live
        record(
            "A: default model", "16 workers x1 shard (no over-partition)", secs, f, live
        )
        secs, f, live = run(
            parallel(m.base, 16, 8, 500, only_supported_types=True),
            _DEFAULT_SIGNAL_TYPES,
        )
        record("A: default model", "16x8, page=500, types= filter", secs, f, live)
    finally:
        m.close()

    # 2. Same per-page cost at page=100, but dominated by fixed per-request cost
    m = Mock(N, S, "--base-ms", "1500", "--per-record-ms", "4.5")
    try:
        start = len(rows)
        secs, f, live = run(stock(m.base))
        rows_base = secs
        record(
            "B: per-request-dominated model", "stock serial, page=100", secs, f, live
        )
        rows[-1]["speedup_vs_stock"] = 1.0
        for label, api in [
            ("1 worker, page=500", parallel(m.base, 1, 1, 500)),
            ("1 worker, page=1000", parallel(m.base, 1, 1, 1000)),
            ("16 workers x8, page=1000", parallel(m.base, 16, 8, 1000)),
        ]:
            secs, f, live = run(api)
            record("B: per-request-dominated model", label, secs, f, live)
            rows[-1]["speedup_vs_stock"] = round(rows_base / secs, 2)
            rows[-1]["real_equiv_hours_for_1.4M"] = round(
                secs / S / 3600 * 1_400_000 / N, 2
            )
    finally:
        m.close()

    # 3. Server-side throughput caps (the question that decides 14x or not)
    for cap_name, extra in [
        ("C: server concurrency cap = 3", ("--max-concurrent", "3")),
        # stock serial at this scale does ~ 1/(0.02*1.95s) = 25 req/s; cap at
        # ~3x that (in scaled time) to model an app-level request rate limit
        ("D: app request-rate cap ~= 3x serial rate", ("--max-rps", "75")),
    ]:
        m = Mock(N, S, *extra)
        try:
            secs, f, live = run(stock(m.base))
            base = secs
            record(cap_name, "stock serial, page=100", secs, f, live)
            rows[-1]["speedup_vs_stock"] = 1.0
            for w in (4, 8, 16, 32):
                page = 100  # keep page equal so only concurrency varies
                secs, f, live = run(parallel(m.base, w, 8, page))
                record(cap_name, f"{w} workers x8, page={page}", secs, f, live)
                rows[-1]["speedup_vs_stock"] = round(base / secs, 2)
            rows[-1]["mock_stats"] = m.stats()
        finally:
            m.close()

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(
            {
                "records": N,
                "scale": S,
                "client_cpu_us_per_record": round(cpu * 1e6, 1),
                "rows": rows,
            },
            fh,
            indent=2,
        )


if __name__ == "__main__":
    main()
