# PoC: faster download and filter-to-CSV for Meta ThreatExchange via the `tx` CLI

Proof-of-concept code for the investigation in [REPORT.md](REPORT.md). Nothing
here is imported by the `threatexchange` package, and no file matches the
repo's pytest globs, so CI ignores it.

| File | What it is |
|---|---|
| `REPORT.md` | Findings, measurements, recommendations, draft issues |
| `synthetic_data.py` | Generates records shaped like Meta TE API `/threat_updates` responses |
| `mock_graph_api.py` | Local mock of `/threat_updates`: paging, time ranges, latency model, throttling, fault injection |
| `parallel_fetch.py` | Time-sharded parallel `fetch_iter()` plus a retrying, throttle-aware Graph client |
| `export_csv.py` | Filter fetched state and write a CSV with chosen columns (the requester's steps 2 and 3) |
| `bench_fetch.py` | Stock vs parallel download benchmark against the mock |
| `bench_storage.py` | Pickle storage and `tx dataset` benchmark at 100K–1.4M records, plus a SQLite comparison |
| `check_poc.py` | Correctness checks (parallel == serial, retries, resume, export == `tx dataset`) |
| `results/` | JSON output from the runs quoted in REPORT.md |

## Running

From `python-threatexchange/`, with the package installed (`pip install -e '.[dev]'`):

```sh
python -m pytest poc/meta_tx_download/check_poc.py -v      # ~15s
python poc/meta_tx_download/bench_fetch.py                  # ~2 min
python poc/meta_tx_download/bench_storage.py                # ~15 min, peaks ~4.5 GB RSS
python poc/meta_tx_download/bench_storage.py --sizes 100000 # ~1 min
```

Exporting from a real `tx fetch` state directory:

```sh
python poc/meta_tx_download/export_csv.py --list-columns
python poc/meta_tx_download/export_csv.py --collab "My Collab" \
    --te-type HASH_PDQ --category POSITIVE_CLASS --tag-any csam --min-owners 2 \
    --rows opinion --columns indicator,owner_app_id,opinion_tags -o out.csv
```

Using the parallel fetcher against the real Meta TE API is **not wired into
`tx fetch`** and has never been run against Meta's servers. See REPORT.md,
"End-to-end validation".
