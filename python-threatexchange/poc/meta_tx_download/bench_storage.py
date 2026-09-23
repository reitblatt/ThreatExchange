# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Measure the CLI's pickle-based fetched-state storage at realistic sizes, and
compare against a minimal SQLite layout.

    python poc/meta_tx_download/bench_storage.py [--sizes 100000 400000 1400000]

For each size, a real TX_STATEDIR is built (collab created through the CLI,
state written through CliSimpleState, the same code path `tx fetch` uses), and
then the real `tx dataset` commands are run in subprocesses. Each subprocess
reports wall time, peak RSS, and how many times pickle.load() was called.
"""

import argparse
import csv
import io
import json
import os
import pathlib
import pickle
import resource
import sqlite3
import subprocess
import sys
import time
import typing as t

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import synthetic_data  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
COLLAB = "Marc"


def _maxrss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def _records(n: int) -> t.Iterator[t.Tuple[t.Tuple[str, str], t.Any]]:
    from threatexchange.exchanges.clients.fb_threatexchange.threat_updates import (
        ThreatUpdateJSON,
    )
    from threatexchange.exchanges.impl.fb_threatexchange_api import (
        FBThreatExchangeIndicatorRecord,
    )

    for r in synthetic_data.iter_records(n, seed=42, delete_frac=0):
        rec = FBThreatExchangeIndicatorRecord.from_threatexchange_json(
            synthetic_data.MY_APP_ID, ThreatUpdateJSON(r)
        )
        if rec is not None:
            yield (r["type"], r["indicator"]), rec


def child_build(n: int, state_dir: str) -> dict:
    """Write state exactly as FetchCommand -> CliSimpleState would."""
    from threatexchange.cli.main import CliState, _get_settings
    from threatexchange.exchanges.fetch_state import FetchDelta
    from threatexchange.exchanges.impl.fb_threatexchange_api import (
        FBThreatExchangeCheckpoint,
        FBThreatExchangeSignalExchangeAPI,
    )

    sd = pathlib.Path(state_dir)
    settings, _ = _get_settings(CliState([], sd).get_persistent_config(), sd)
    store = settings.fetched_state.get_for_api(FBThreatExchangeSignalExchangeAPI)
    updates = dict(_records(n))
    delta = FetchDelta(updates, FBThreatExchangeCheckpoint(synthetic_data.END_TS))
    t0 = time.monotonic()
    store._write_state(COLLAB, delta)
    dump = time.monotonic() - t0
    return {
        "records": len(updates),
        "pickle_dump_sec": round(dump, 2),
        "pickle_mb": round(store.collab_file(COLLAB).stat().st_size / 2**20, 1),
        "build_rss_mb": round(_maxrss_mb()),
    }


def child_load(state_dir: str) -> dict:
    path = next(pathlib.Path(state_dir, "fetched").rglob("*.state.pickle"))
    import threatexchange.exchanges.impl.fb_threatexchange_api  # noqa: F401

    t0 = time.monotonic()
    with path.open("rb") as f:
        pickle.load(f)
    return {
        "pickle_load_sec": round(time.monotonic() - t0, 2),
        "pickle_load_rss_mb": round(_maxrss_mb()),
    }


def child_cli(state_dir: str, argv: t.List[str]) -> dict:
    """Run the real CLI in-process, counting pickle.load() calls."""
    from threatexchange.cli import main as cli_main

    loads = 0
    real_load = pickle.load

    def counting_load(*a: t.Any, **kw: t.Any) -> t.Any:
        nonlocal loads
        loads += 1
        return real_load(*a, **kw)

    pickle.load = counting_load  # type: ignore
    out = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = out
    t0 = time.monotonic()
    try:
        cli_main.inner_main(argv, pathlib.Path(state_dir))
    finally:
        sys.stdout = real_stdout
    return {
        "cmd": "tx " + " ".join(argv),
        "wall_sec": round(time.monotonic() - t0, 2),
        "peak_rss_mb": round(_maxrss_mb()),
        "pickle_loads": loads,
        "output_lines": out.getvalue().count("\n"),
    }


def child_sqlite(n: int, db_path: str) -> dict:
    """A minimal relational layout: one row per (indicator, owner opinion)."""
    if os.path.exists(db_path):
        os.unlink(db_path)
    db = sqlite3.connect(db_path)
    db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE opinion (
            collab TEXT, te_type TEXT, indicator TEXT,
            owner_app_id INTEGER, descriptor_id INTEGER,
            category TEXT, is_mine INTEGER, tags TEXT
        );
        """)

    def rows(it):
        for (ty, ind), rec in it:
            for o in rec.opinions:
                yield (
                    COLLAB,
                    ty,
                    ind,
                    o.owner_app_id,
                    o.descriptor_id,
                    o.category.name,
                    int(o.is_mine),
                    " ".join(sorted(o.tags)),
                )

    data = list(rows(_records(n)))
    t0 = time.monotonic()
    with db:
        db.executemany("INSERT INTO opinion VALUES (?,?,?,?,?,?,?,?)", data)
        db.execute("CREATE INDEX ix ON opinion (collab, te_type, indicator)")
    full_write = time.monotonic() - t0

    # Incremental write of one 500-record page (what a checkpoint *should* cost)
    page = data[:1000]
    t0 = time.monotonic()
    with db:
        keys = {(r[1], r[2]) for r in page}
        db.executemany(
            "DELETE FROM opinion WHERE collab=? AND te_type=? AND indicator=?",
            [(COLLAB, a, b) for a, b in keys],
        )
        db.executemany("INSERT INTO opinion VALUES (?,?,?,?,?,?,?,?)", page)
    page_write = time.monotonic() - t0

    # Same selection as `tx dataset -P --csv -s pdq -t csam` (any opinion
    # carries the tag => emit the indicator once), so row counts must match.
    t0 = time.monotonic()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator"])
    cnt = 0
    for row in db.execute(
        "SELECT DISTINCT indicator FROM opinion "
        "WHERE te_type='HASH_PDQ' AND (' ' || tags || ' ') LIKE '% csam %'"
    ):
        w.writerow(row)
        cnt += 1
    query = time.monotonic() - t0
    db.close()
    return {
        "sqlite_full_write_sec": round(full_write, 2),
        "sqlite_mb": round(os.path.getsize(db_path) / 2**20, 1),
        "sqlite_page_upsert_ms": round(page_write * 1000, 1),
        "sqlite_filter_to_csv_sec": round(query, 2),
        "sqlite_filter_rows": cnt,
    }


def _child(*args: str) -> dict:
    out = subprocess.run(
        [sys.executable, __file__, "--child", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[100000, 400000, 1400000])
    ap.add_argument("--workdir", default=os.path.join(HERE, "results", "_state"))
    ap.add_argument("--out", default=os.path.join(HERE, "results", "storage.json"))
    if sys.argv[1:2] == ["--child"]:
        mode, *rest = sys.argv[2:]
        if mode == "build":
            res = child_build(int(rest[0]), rest[1])
        elif mode == "load":
            res = child_load(rest[0])
        elif mode == "cli":
            res = child_cli(rest[0], rest[1:])
        else:
            res = child_sqlite(int(rest[0]), rest[1])
        print(json.dumps(res))
        return
    a = ap.parse_args()

    results = []
    for n in a.sizes:
        sd = os.path.join(a.workdir, f"n{n}")
        subprocess.run(["rm", "-rf", sd], check=True)
        env = dict(os.environ, TX_STATEDIR=sd)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "threatexchange.cli.main",
                "config",
                "collab",
                "edit",
                "fb_threatexchange",
                "--create",
                COLLAB,
                "--privacy-group",
                "1234567890",
            ],
            check=True,
            env=env,
        )
        row: t.Dict[str, t.Any] = {"n": n}
        row.update(_child("build", str(n), sd))
        row.update(_child("load", sd))
        row["cli"] = [
            _child("cli", sd, "dataset"),
            _child("cli", sd, "dataset", "-P", "--csv"),
            _child("cli", sd, "dataset", "-P", "--csv", "-s", "pdq", "-t", "csam"),
            _child("cli", sd, "dataset", "--rebuild-indices"),
        ]
        row.update(_child("sqlite", str(n), os.path.join(sd, "state.sqlite")))
        print(json.dumps(row, indent=1), flush=True)
        results.append(row)
        subprocess.run(["rm", "-rf", sd], check=True)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(results, fh, indent=2)


if __name__ == "__main__":
    main()
