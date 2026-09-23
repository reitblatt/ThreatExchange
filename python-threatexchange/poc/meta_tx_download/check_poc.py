# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Correctness checks for the PoC. Not named test_*.py on purpose so the repo's
CI `py.test` doesn't collect it. Run explicitly:

    python -m pytest poc/meta_tx_download/check_poc.py -v
"""

import os
import sys
import threading
import time
import typing as t

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mock_graph_api  # noqa: E402
import synthetic_data  # noqa: E402
from parallel_fetch import (  # noqa: E402
    GraphRequestError,
    ParallelFBThreatExchangeSignalExchangeAPI,
    RetryingGraphClient,
)
from threatexchange.exchanges.clients.fb_threatexchange.api import (  # noqa: E402
    ThreatExchangeAPI,
)
from threatexchange.exchanges.impl.fb_threatexchange_api import (  # noqa: E402
    FBThreatExchangeCollabConfig,
    FBThreatExchangeSignalExchangeAPI,
)

TOKEN = f"{synthetic_data.MY_APP_ID}|abcdefghijklmnopqrstuvwxyz"
PG = 1234567890


def _serve(records, **cfg) -> t.Tuple[str, mock_graph_api.ThreadingHTTPServer]:
    cfg.setdefault("base_ms", 0)
    cfg.setdefault("per_record_ms", 0)
    server = mock_graph_api.make_server(records, mock_graph_api.MockConfig(**cfg))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/v21.0", server


def _stop(server) -> None:
    server.shutdown()
    server.server_close()


def _collab() -> FBThreatExchangeCollabConfig:
    return FBThreatExchangeCollabConfig(name="c", privacy_group=PG)


def _stock(base: str) -> FBThreatExchangeSignalExchangeAPI:
    return FBThreatExchangeSignalExchangeAPI(
        ThreatExchangeAPI(TOKEN, endpoint_override=base), _collab()
    )


def _parallel(base: str, **kw) -> ParallelFBThreatExchangeSignalExchangeAPI:
    api = ParallelFBThreatExchangeSignalExchangeAPI(
        ThreatExchangeAPI(TOKEN, endpoint_override=base), _collab()
    )
    graph_kw = {k: kw.pop(k) for k in list(kw) if k in ("max_attempts", "read_timeout")}
    for k, v in kw.items():
        setattr(api, k, v)
    api.graph = RetryingGraphClient(
        pool_size=api.workers, backoff_base=0.01, backoff_max=0.2, **graph_kw
    )
    return api


def _fold(deltas, state=None):
    state = {} if state is None else state
    last_cp = None
    for d in deltas:
        if last_cp is not None:
            assert last_cp.update_time <= d.checkpoint.update_time, "rewound"
        last_cp = d.checkpoint
        FBThreatExchangeSignalExchangeAPI.naive_fetch_merge(state, d.updates)
    return state, last_cp


def _norm(state):
    return {k: repr(v) for k, v in state.items()}


@pytest.fixture(scope="module")
def records():
    return synthetic_data.generate(6000, seed=7)


def test_parallel_matches_serial(records):
    base, server = _serve(records, max_limit=500)
    try:
        serial, _ = _fold(_stock(base).fetch_iter([], None))
        for workers, spw in [(1, 1), (4, 1), (8, 8), (16, 4)]:
            par, _ = _fold(
                _parallel(
                    base, workers=workers, shards_per_worker=spw, page_size=137
                ).fetch_iter([], None)
            )
            assert _norm(par) == _norm(serial), (workers, spw)
        live = sum(1 for r in records if not r["should_delete"])
        assert 0 < len(serial) <= live
    finally:
        _stop(server)


def test_stock_client_does_not_retry_5xx(records):
    """get_json_from_url uses requests.get, not the retrying session."""
    base, server = _serve(records, fail_every=5)
    try:
        with pytest.raises(requests.HTTPError):
            _fold(_stock(base).fetch_iter([], None))
        assert server.RequestHandlerClass.state.request_count == 5  # type: ignore
    finally:
        _stop(server)


def test_parallel_retries_5xx_and_throttling(records):
    base, server = _serve(records, max_limit=500)
    ref, _ = _fold(_stock(base).fetch_iter([], None))
    _stop(server)
    base, server = _serve(records, fail_every=5, max_rps=40)
    try:
        api = _parallel(base, workers=8, page_size=100)
        par, _ = _fold(api.fetch_iter([], None))
        assert _norm(par) == _norm(ref)
        st = server.RequestHandlerClass.state  # type: ignore
        assert st.failed_count > 0 and st.throttled_count > 0
        assert api.graph and api.graph.stats["retries"] > 0
    finally:
        _stop(server)


def test_parallel_resume_after_failure(records):
    base, server = _serve(records, max_limit=500)
    ref, _ = _fold(_stock(base).fetch_iter([], None))
    _stop(server)

    # Fail hard (no retries) partway through
    base, server = _serve(records, fail_every=23)
    got: list = []
    with pytest.raises(GraphRequestError):
        for d in _parallel(base, workers=4, page_size=50, max_attempts=1).fetch_iter(
            [], None
        ):
            got.append(d)
    _stop(server)
    assert got, "expected some progress before failure"
    partial, cp = _fold(got)
    assert len(partial) < len(ref)

    # Resume from the persisted checkpoint against a healthy server
    base, server = _serve(records)
    try:
        final, _ = _fold(
            _parallel(base, workers=4, page_size=50).fetch_iter([], cp), partial
        )
        assert _norm(final) == _norm(ref)
    finally:
        _stop(server)


def test_stock_client_waits_out_stall_parallel_times_out(records):
    base, server = _serve(records, hang_at={2}, hang_sec=3)
    try:
        t0 = time.monotonic()
        _fold(_stock(base).fetch_iter([], None))
        stock_elapsed = time.monotonic() - t0
        assert stock_elapsed >= 3, "stock client waited out the full stall"
    finally:
        _stop(server)
    base, server = _serve(records, hang_at={2}, hang_sec=3)
    try:
        t0 = time.monotonic()
        _fold(_parallel(base, workers=2, read_timeout=0.5).fetch_iter([], None))
        assert time.monotonic() - t0 < 3
    finally:
        _stop(server)


# --- export_csv (filter -> CSV) ---


@pytest.fixture(scope="module")
def state_dir(tmp_path_factory):
    import bench_storage
    from threatexchange.cli import main as cli_main

    sd = tmp_path_factory.mktemp("txstate")
    cli_main.inner_main(
        [
            "config",
            "collab",
            "edit",
            "fb_threatexchange",
            "--create",
            bench_storage.COLLAB,
            "--privacy-group",
            "1234567890",
        ],
        sd,
    )
    bench_storage.child_build(3000, str(sd))
    return sd


def _export(sd, *argv) -> t.List[dict]:
    import csv
    import io

    import export_csv

    buf = io.StringIO()
    export_csv.Exporter(
        export_csv.get_argparse().parse_args(["--state-dir", str(sd), *argv])
    ).run(buf)
    buf.seek(0)
    return list(csv.DictReader(buf))


def test_export_matches_tx_dataset(state_dir, capsys):
    from threatexchange.cli import main as cli_main

    cli_main.inner_main(["dataset", "-P", "-S", "-s", "pdq", "-t", "csam"], state_dir)
    expected = set(capsys.readouterr().out.split())
    rows = _export(
        state_dir,
        "--te-type",
        "HASH_PDQ",
        "--tag-any",
        "csam",
        "--columns",
        "indicator",
    )
    assert expected and {r["indicator"] for r in rows} == expected


def test_export_filters(state_dir):
    import bench_storage

    records = dict(bench_storage._records(3000))
    owner = synthetic_data.OWNER_APPS[3]

    rows = _export(
        state_dir,
        "--rows",
        "opinion",
        "--owner",
        str(owner),
        "--category",
        "POSITIVE_CLASS",
        "--tag-none",
        "hate",
        "--min-owners",
        "2",
        "--columns",
        "te_type,indicator,owner_app_id,opinion_category,n_owners,tags",
    )
    expected = set()
    for (ty, ind), rec in records.items():
        tags = {tg for o in rec.opinions for tg in o.tags}
        owners = {o.owner_app_id for o in rec.opinions}
        if "hate" in tags or len(owners) < 2:
            continue
        for o in rec.opinions:
            if o.owner_app_id == owner and o.category.name == "POSITIVE_CLASS":
                expected.add((ty, ind))
    assert expected
    assert {(r["te_type"], r["indicator"]) for r in rows} == expected
    for r in rows:
        assert r["owner_app_id"] == str(owner)
        assert r["opinion_category"] == "POSITIVE_CLASS"
        assert int(r["n_owners"]) >= 2
        assert "hate" not in r["tags"].split()


def test_export_includes_types_dataset_cannot_show(state_dir):
    rows = _export(state_dir, "--te-type", "HASH_TMK", "HASH_SHA1")
    assert rows, "unmapped TE types are stored but invisible to `tx dataset`"
