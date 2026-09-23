# Downloading and slicing Meta ThreatExchange data with the `tx` CLI: scoping report

**Status:** investigation + proof of concept. Nothing in `threatexchange/` has been changed.
**Date:** 2026-09-23.

## Terminology

Two unrelated things share the name "ThreatExchange". This report keeps them apart:

- **`tx` CLI / python-threatexchange**: the open-source library and CLI in this repo (`pip install threatexchange`).
- **Meta TE API**: Meta's hosted ThreatExchange service, reached through the Facebook Graph API (`graph.facebook.com/vNN.0/<privacy_group>/threat_updates`).

The request is about using the `tx` CLI to download from the Meta TE API. Its code path is `tx fetch` → `FBThreatExchangeSignalExchangeAPI.fetch_iter()` (`threatexchange/exchanges/impl/fb_threatexchange_api.py`) → `ThreatExchangeAPI` (`threatexchange/exchanges/clients/fb_threatexchange/api.py`).

## What I could and could not verify

- **No Meta TE API token is available in this workspace.** `TX_ACCESS_TOKEN` is unset, and `~/.txtoken` and `~/.threatexchange` do not exist. Those are the places the CLI looks. I did not search further, as instructed.
- So **nothing here was measured against Meta's servers.** Every download speed number below comes from a local mock of `/threat_updates` (`mock_graph_api.py`). The mock uses a latency model I *chose*, calibrated to Meta's own published throughput figure.
- These are **real measurements**:
  - client-side CPU cost
  - the parallel client's correctness and resume behavior
  - the stock client's failure behavior
  - everything about storage and `tx dataset`, which runs the real CLI code on synthetic data shaped like real `/threat_updates` responses
- The synthetic data's *distribution* (type mix, tags, owners, time skew) is invented. Its *shape* matches the fields the CLI requests.

Each claim below is tagged **[measured]**, **[code]** (read directly from source), **[docs]** (Meta's published docs), or **[estimate]**.

---

## Top findings, ranked by user value ÷ implementation cost

| # | Finding | Value to Marc & users | Cost | Recommendation |
|---|---|---|---|---|
| 1 | Graph API **v21.0 is hardcoded and expires 2027-01-21** [docs, code] | Critical: after that date `tx fetch` (and HMA's TE fetcher) stop working for everyone | ~1 line (+ make it configurable) | **Do now** |
| 2 | **GET retries and timeouts have never been active.** `get_json_from_url` calls `requests.get`, not the retrying session. This has been true since Feb 2021 (#372) [code, measured] | High: an unattended multi-hour download dies on the first transient 5xx, or hangs forever on a stalled socket | ~1 line to fix the typo; ~50 lines to do it properly | **Do now** |
| 3 | `tx dataset` **unpickles the whole collab once per signal type** (7×), and cyclic GC thrashes during each load [measured] | High: 113s → **9.4s** and 4.4 GB → 2.5 GB RSS at 1.4M records. This also hits the index rebuild that runs after *every* `tx fetch` | Small: cache the store in `CLISettings`, pause GC around `pickle.load` | **Do now** |
| 4 | Marc's filter → CSV gap: no filtering by category, owner, tag-all/none, or raw TE type; no column choice; no per-opinion rows [code] | High: this *is* Marc's stated need | Small–medium (PoC `export_csv.py` is ~250 lines incl. docs) | **Do next** (issue drafted) |
| 5 | Parallel download via `start_time`/`stop_time` sharding works, and matches serial output exactly [measured on mock] | Potentially high, **but the ceiling is set by Meta's server-side throttling, which I could not observe** | Medium (~300 lines in the PoC; production needs adaptive concurrency) | **Validate with a real token first** (15-min probe, below) |
| 6 | Some fields Marc may want as CSV columns are **never stored**: `last_updated`, `added_on`, description, confidence, severity, review status [code] | Medium: depends on what columns Marc actually needs | Medium: widens the record type; pickle compat shims | Ask Marc which columns he needs before building |
| 7 | Reference client v2 | Low on its own; items 1+2 get most of the value | Large | **Not now**; targeted hardening instead |
| 8 | Replace pickle storage | Medium long-term; most of the *speed* pain is fixed by #3 | Large | **Not now**; revisit together with #6 |

---

## Marc's workflow, mapped to today's CLI

```sh
tx config collab edit fb_threatexchange --create Marc --privacy-group <ID>
TX_ACCESS_TOKEN=... tx fetch                  # step 1: download everything
tx dataset -P --csv -c Marc -s pdq -t <tag>   # steps 2+3: filter, emit CSV
```

Step 1 works but is slow (§a). Steps 2 and 3 work only for filters on collab, signal type, content type, and "has any of these tags". The CSV always has exactly `signal_type,signal_str,collab,category,tags` (§d).

---

## (a) Download speed and hardening *(priority)*

### How the download works today [code]

1. `fetch_iter` opens **one** cursor over `/threat_updates` with `page_size=100` and fields `indicator,type,last_updated,should_delete,descriptors{id,reactions,owner{id},tags,status}`.
2. It walks `paging.next` strictly serially. There is exactly one request in flight at any time.
3. Each page becomes a `FetchDelta`, which is merged into an in-memory dict. The whole dict is pickled to disk every `--checkpoint-every` seconds (default 600) and at exit.
4. After the fetch, `tx fetch` rebuilds all match indices from the full dataset.

### Why it takes about 7 hours

- **Meta documents the bottleneck themselves** [docs, [threat_updates reference](https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-updates/)]:
  > "if resolving all nested fields from `threat_updates`, you might be able to process ~200,000 records an hour, but by splitting the calls, you are usually limited only by the speed of getting new ids from `threat_updates`, which can be many multiples faster."

  The CLI resolves exactly those nested `descriptors{...}` fields.
- **7 hours × ~200K records/hour ≈ 1.4M records** [estimate]. If Marc's privacy group is about that size, the 7 hours is fully explained by server-side per-record cost at the documented rate. If his group is much *smaller*, per-request overhead dominates instead, and page size matters much more (see model B below). I don't know his group's size. That is the first thing to ask.
- **Client-side CPU is not the bottleneck.** JSON decode plus record conversion costs **5.7 µs/record** [measured]. That's about 8 seconds for 1.4M records. Threads (despite the GIL) are fine for parallelizing.
- **Pickle checkpointing is not the bottleneck.** A full dump at 1.4M records takes 9.9s [measured]. About 42 checkpoints over 7 hours, averaging half that size, comes to roughly 3–4 minutes, under 1% [estimate].
- **Connection reuse is missing.** Every page opens a fresh TCP+TLS connection because of the `requests.get` bug [code]. That's likely 100–300 ms per request [estimate], which is small next to about 2s of server time per 100-record page.

### Does rate limiting cap concurrency? *I could not determine this, and it decides everything.*

What the docs say [docs]:

- The Graph API app-level limit is `200 × (daily active users)` calls/hour, **per app**. A multi-ID request counts as one call *per ID*. Throttling comes back as error codes 4, 17, 32, or 613. The `X-App-Usage` header reports `call_count`, `total_cputime`, and `total_time` as a percentage of the budget ([rate-limiting docs](https://developers.facebook.com/docs/graph-api/overview/rate-limiting/)).
- The `/threat_updates` page states no explicit rate limit. It only says not to *poll* more often than once a minute (about incremental polling, not paging).

What that means [estimate]:

- A ThreatExchange app is typically a server-side integration with near-zero "daily active users". I don't know how Meta applies the DAU formula to such apps, or whether ThreatExchange has its own quota.
- Heavy nested-field queries are exactly what `total_cputime` / `total_time` meter. Running N of them concurrently multiplies that consumption N-fold. If Meta throttles on CPU time, the speedup is capped at roughly (budget ÷ serial usage), **however many workers we run**.
- Meta's recommended alternative (fetch IDs only, then resolve them in batches by ID) can be "many multiples faster" per their docs. But under the call-counting rule, a 50-ID lookup costs 50 calls. That trades CPU-time pressure for call-count pressure. The per-request ID limit of 50 is general Graph API behavior; I have not verified it for ThreatExchange.

### Parallel PoC results [measured, on the mock]

`parallel_fetch.py` is a drop-in subclass of `FBThreatExchangeSignalExchangeAPI`. It works like this:

- It cuts `[earliest, now)` into `workers × 8` time shards.
- A thread pool fetches the shards.
- Deltas are yielded in time order. The checkpoint only advances past fully completed prefixes, so the store's last-write-wins merge (including tombstones) produces the same state as a serial fetch.

`check_poc.py` verifies an identical final state (every record compared by `repr`) against the stock serial fetch across 4 worker/shard configs. It also checks recovery from 5xx errors and throttling, and resume after a hard failure.

Mock parameters:

- Latency model: `150 ms/request + 18 ms/record` when nested fields are requested. That's ≈185K records/hour serially at page 100, matching Meta's figure.
- Data: 20K records, run at 1/50 time scale.
- "Real-equivalent hours" linearly extrapolates to 1.4M records.
- The benchmark ran twice; every speedup matched to within about 5%.

| Scenario | Config | Speedup vs stock | Real-equiv. hours @1.4M |
|---|---|---|---|
| **A: uncapped server** | stock serial, page=100 | 1.0× | 8.2 |
| | 1 worker, page=500 / 1000 | 1.09× / 1.11× | 7.6 / 7.4 |
| | 4 workers | 3.8× | 2.2 |
| | 8 workers | 6.5× | 1.3 |
| | 16 workers | 10.0× | 0.82 |
| | 32 workers | 12.1× | 0.68 |
| | 16 workers, **no over-partitioning** (1 shard each) | 7.3× | 1.1 |
| **B: per-request-dominated** (1500 ms + 4.5 ms/rec; same cost per 100-record page) | 1 worker, page=500 / 1000 | 2.4× / 3.0× | 3.4 / 2.7 |
| | 16 workers, page=1000 | 12.8× | 0.64 |
| **C: server serves at most 3 concurrent requests** | 4 / 8 / 16 / 32 workers | 1.7× / 2.6× / 2.9× / 2.8× | 4.7 / 3.2 / 2.8 / 2.9 |
| **D: app request-rate cap ≈ 3× serial rate** | 4 / 8 / 16 / 32 workers | 1.8× / 2.3× / **1.8× / 1.5×** | 4.6 / 3.6 / 4.6 / 5.6 |

What this shows:

- **Even in the ideal mock, 14× (7 h → 30 min) needs about 32 concurrent streams and still falls slightly short** (12×). Promising 30 minutes requires Meta to serve 16–32 concurrent heavy queries per app at full per-stream speed. Nobody has verified that.
- **With any server-side cap, the ceiling is the cap, not the worker count** (scenario C).
- **With a request-rate cap, too many workers is *worse* than a few** (scenario D: 32 workers came out slower than 8), because of throttle/backoff churn. A production version needs adaptive concurrency (for example AIMD driven by throttle errors and `X-App-Usage`), not a fixed `--workers 32`.
- **Bursty data needs over-partitioning.** With equal time slices, 16 workers got 7.3×; with 8× more, smaller slices they got 10×.
- **Page size is a free knob whose value depends on an unknown split** between per-request and per-record cost: 1.1× in model A, 3× in model B.
- The `types=` filter (fetching only indicator types the CLI can use) saved 8% of records on my synthetic mix. Real savings depend entirely on Marc's type mix.

**Realistic ceiling** [estimate]:

- I would not promise anything beyond "several-fold, pending measurement".
- Plausible range: roughly 1.5× (if Meta throttles on CPU time near serial usage) up to about 10× (if it doesn't throttle below 16 streams).
- Separately, the documented two-phase fetch *might* beat both, subject to call-count limits.
- A 15-minute probe with a real token settles this (see "End-to-end validation").

### What happens today when a request fails mid-download? [code, measured]

- **Transient 5xx or throttle error:** not retried, because of the `requests.get` typo. The `Retry(total=4, status_forcelist=[429,500,…], backoff_factor=0.2)` configuration never takes effect. Even if it did, it would not catch Graph throttling (4xx with `error.code` 4/17/32/613) and would give up after about 1.5s. `check_poc.py::test_stock_client_does_not_retry_5xx` confirms the stock fetch aborts on the first 500.
- **Stalled connection:** `requests.get` without `timeout=` never times out, so the process hangs without progress and without an error. The mock test shows the stock client waiting out a full stall. The "forever" part comes from reading the code: requests' default is no timeout.
- **Progress is not lost.** `FetchCommand` catches the exception, `finally: store.flush()` persists everything merged so far along with its checkpoint, and it exits with code 3. Re-running resumes from the last `last_updated` seen. A hard kill (OOM or SIGKILL) loses up to `--checkpoint-every` (10 min).
- **So the practical cost is about babysitting.** The work done isn't lost. An overnight run stops at the first blip and waits for a human to notice.
- **The 85-day cliff:** if the stored checkpoint is more than 85 days old (Meta keeps deletes for 90), `tx fetch` wipes state and **re-downloads everything**. If Marc fetches only occasionally, *every* run is a full 7-hour download. A daily cron avoids that.

### Draft issue (a1): Fix retries/timeouts for Meta TE API GETs

> **Title:** `[pytx] ThreatExchangeAPI GETs bypass the retrying session: no retries, no timeouts`
>
> `ThreatExchangeAPI.get_json_from_url` opens a session with a `TimeoutHTTPAdapter` + `Retry`, then calls the module-level `requests.get(url, ...)` instead of `session.get(...)`. This has been the case since #372 (Feb 2021), and there's a `# !!! Typo?` comment on the line. As a result, every `/threat_updates` page (and every other GET) has no retry, no timeout, and no connection reuse. A multi-hour `tx fetch` aborts on the first transient 5xx and can hang forever on a stalled socket. HMA's fetcher uses the same path.
>
> Fix:
> 1. Use one long-lived `requests.Session` per `ThreatExchangeAPI`, and call `session.get`.
> 2. Set (connect, read) timeouts.
> 3. Retry connection errors, timeouts, 5xx, 429, **and** Graph throttle codes 4/17/32/613, which arrive as 4xx with a JSON `error.code`, so `status_forcelist` alone misses them. Use exponential backoff with jitter; throttle waits should be measured in minutes, not attempts.
> 4. Surface the Graph `error` body in the raised exception.
>
> Reference implementation: `poc/meta_tx_download/parallel_fetch.py::RetryingGraphClient`, with tests in `check_poc.py`.

### Draft issue (a2): Measure before parallelizing `tx fetch`

> **Title:** `[pytx] Faster initial fetch from Meta ThreatExchange: measure throttling, then parallelize`
>
> A full initial fetch of a large privacy group reportedly takes about 7 hours, consistent with Meta's documented ~200K records/hour for nested `threat_updates` fields. `/threat_updates` supports `start_time`/`stop_time`, so time-sharded parallel fetch is possible. A PoC (`poc/meta_tx_download/parallel_fetch.py`) matches serial output exactly and scales 10–12× on a mock *with no server-side throttling*. Under a capped mock, it plateaus at the cap, and too many workers makes it slower.
>
> Before building it, run the probe in REPORT.md with a real token to learn:
> - per-page latency vs `limit`
> - whether latency or throttling degrades at 2/4/8/16 concurrent streams
> - what `X-App-Usage` reports
>
> Then pick the smaller of:
> - (a) page size + `types=` filter + retries only
> - (b) time-sharded fetch with adaptive concurrency
> - (c) Meta's two-phase ids-then-batch-lookup approach
>
> Don't promise a specific speedup before the probe.

---

## (d) Slicing and CSV output *(priority: this is Marc's actual need)*

### What `tx dataset` supports today [code]

| Capability | Today |
|---|---|
| Filter by collab | `-c NAME…` |
| Filter by signal type / content type | `-s pdq…` / `-C photo…` (mutually exclusive) |
| Filter by tag | `-t TAG…`: *any* opinion has *any* of the tags |
| Filter by category (positive / disputed / negative / seed) | **no** |
| Filter by owner app (a specific member, or "not mine") | **no** |
| Tag AND / tag NOT | **no** |
| Raw TE indicator type (e.g. `HASH_TMK`) | **no**. Types with no python-threatexchange SignalType are stored but **invisible** to `dataset` |
| CSV columns | fixed: `signal_type,signal_str,collab,category,tags` |
| One row per opinion (owner, descriptor id, that owner's status and tags) | **no**. Only the aggregate is printed |
| Fields not stored at all: `last_updated`, `added_on`, description, confidence, severity, review status | **impossible** without fetch/storage changes |

### The gap, concretely

For "download everything → filter → CSV with chosen columns", Marc can do the first and a coarse version of the second. He cannot choose columns, filter on owner or category, or see per-member opinions. `-P` output is also unordered, and at 1.4M records it takes about 2 minutes (see §c).

### PoC: `export_csv.py` [measured]

`export_csv.py` reads the CLI's existing fetched state read-only, loading it once. It adds:

- `--te-type`, `--signal-type`
- `--tag-any` / `--tag-all` / `--tag-none`
- `--category`
- `--owner` / `--exclude-owner`
- `--min-owners N` (for example, only hashes corroborated by ≥2 members)
- `--rows indicator|opinion`
- `--columns` chosen from `collab, te_type, signal_type, indicator, category, tags, owners, n_owners, owner_app_id, descriptor_id, opinion_category, opinion_tags, is_mine`
- `--list-columns`

`check_poc.py` tests it three ways:

- Its output for `--te-type HASH_PDQ --tag-any csam` is **set-identical to the real `tx dataset -P -S -s pdq -t csam`**.
- Compound filters match a brute-force expectation.
- It surfaces types that `dataset` can't show.

At 1.4M synthetic records, three typical queries took 13–25s wall time and 2.5 GB peak RSS, dominated by the single pickle load.

### Draft issue (d): Filter and column selection for `tx dataset`

> **Title:** `[pytx] tx dataset: category/owner/tag filters, raw TE types, and --columns for CSV export`
>
> Use case: a ThreatExchange member downloads their whole privacy group with `tx fetch`, then wants a CSV restricted by category, member, and tags, with specific columns. Today `tx dataset --csv` has fixed columns, only filters by any-of-tags, and hides TE indicator types that have no SignalType.
>
> Proposal (all filters ANDed; values within a flag ORed):
> - `--only-categories`
> - `--only-owners` / `--exclude-owners`
> - `--tags-all` / `--exclude-tags`
> - `--min-owners`
> - `--only-te-types`
> - `--rows indicator|opinion`
> - `--columns a,b,c` / `--list-columns`
>
> Load each collab's state once. PoC with tests: `poc/meta_tx_download/export_csv.py`.
>
> Open question for the requester: which *extra* fields are needed? `last_updated` and descriptor `added_on` are dropped at fetch time today. Adding them changes the stored record type (a pickle-compat concern, see storage issue).

---

## (b) Reference client v2 *(assess only)*

**What's wrong today** [code]:

1. **The Graph API version is pinned to `v21.0`, which expires 2027-01-21.** The last bump (#1647, Oct 2024) was a one-line change.
2. The retry, timeout, and session bug from §a. The retry policy would also be wrong if it ran: no Graph throttle codes, and about 1.5s of total backoff.
3. `api.py` begins "This is an entire copy of a file from ThreatExchange/hashing. TODO: Slim down to only what we need". It is 656 lines of mostly untyped, dict-in/dict-out code. Of its methods, only `get_threat_updates`, the privacy-group lookups, and `get_json_from_url` have callers in this repo (CLI + HMA).
4. The descriptor write paths (upload, copy, react, delete), `get_tag_id`, and `get_threat_descriptors` have no callers in this repo. They are still public API for pip users.
5. `threat_updates.py`'s `ThreatUpdatesDelta`, `ThreatUpdatesStore`, and `ThreatUpdateFileStore`, including a `split()` "parallelization trick" that looks broken (`new_start` never advances), have no callers outside their own file. The same goes for `cli/dataset/simple_serialization.py` (`CliIndicatorSerialization`, `HMASerialization`, for the retired AWS HMA).
6. HTTP errors surface as bare `HTTPError`, and the Graph `error` JSON that explains the failure is lost.

**Cost to users:** items 1 and 2 are the real harm. Items 3–6 cost maintainers and confuse readers; they don't cost users.

**What a v2 would involve** [estimate]:

- a small typed transport (session, timeouts, throttle-aware retries, paging iterator, configurable API version)
- typed `/threat_updates` records
- deleting or deprecating the dead code
- keeping `FBThreatExchangeSignalExchangeAPI`'s public surface stable, since HMA depends on it

**Recommendation: don't do a v2 now.** Do the targeted fixes: the version bump plus a configurable version, and issue a1. They deliver about 90% of the user value in about a day. Revisit a v2 only if the (a2) probe says the two-phase ids-then-lookup fetch is the way forward, because that needs a new request pattern anyway. Mark the dead code deprecated in the meantime.

### Draft issue (b): Graph API version expiry

> **Title:** `[pytx] Graph API v21.0 expires 2027-01-21: bump and make configurable`
>
> `ThreatExchangeAPI._TE_BASE_URL` is hardcoded to `https://graph.facebook.com/v21.0`. Per Meta's version table, v21.0 is available until 2027-01-21, and the current version is v26.0. After that date, `tx fetch` and HMA's ThreatExchange fetcher stop working. Bump to a current version, run the TE e2e path with a real token, and allow an override (env var or constructor argument) so the next expiry doesn't need a release.

---

## (c) Pickle-based storage *(assess only)*

**How it works** [code]:

- One pickle file per collab (`~/.threatexchange/fetched/<api>/<collab>.state.pickle`) holds the entire `FetchDelta`.
- It is written atomically (temp file + rename), so it's crash-safe.
- It is loaded fully into memory on any read and rewritten fully on every flush.

**Measured, 1.4M synthetic records** (`bench_storage.py`, real CLI code) [measured]:

| | 100K | 400K | 1.4M |
|---|---|---|---|
| pickle size | 16 MB | 65 MB | 229 MB |
| one full dump / load | 0.5 / 0.5 s | 2.1 / 2.3 s | 9.9 / 9.0 s |
| RSS after one load | 207 MB | 737 MB | 2.5 GB |
| `tx dataset` (summary) | 7.8 s, 389 MB | 30 s, 1.3 GB | **113 s, 4.4 GB** |
| `tx dataset -P --csv` | 7.4 s | 32 s | **114 s**, 2.9 GB |
| `tx dataset --rebuild-indices` (runs after every `tx fetch`) | 7.1 s | 31 s | **111 s, 4.6 GB** |
| `tx dataset -P --csv -s pdq -t csam` | 0.9 s | 4.0 s | 11.8 s |
| pickle loads per unfiltered `dataset` | 7 | 7 | 7 |

**Where the time goes:**

- **It's mostly not pickle's fault.** `CLISettings.fetched_state.get_for_api()` builds a *new* `CliSimpleState` on every call. `DatasetCommand.get_signals()` calls it once per signal type, so the file is unpickled 7 times, and all 7 copies stay alive, which explains the RSS.
- During each load, CPython's cyclic GC repeatedly rescans millions of freshly allocated objects. At 100K records: 7.6s baseline; **0.90s** with load-once; 0.72s with load-once plus a GC pause during `pickle.load`. At 1.4M: **113s → 9.4s**, and 4.4 GB → 2.5 GB [measured, via monkeypatch].
- The backward-compat `__setstate__` shims on the opinion classes make each load **1.7× slower** [measured, 100K records, median of 5].

**The genuine downsides of pickle** [code; costs estimated]:

- **Whole-dataset-in-memory for every command.** At 1.4M records, 2.5 GB just to read is too much for small machines. Nothing can stream.
- **Whole-file rewrite per checkpoint:** 9.9s at 1.4M. SQLite upserts a page in about **15 ms** [measured]. That's minor during a 7-hour fetch, but it grows linearly.
- **Opaque.** Marc can't open it in pandas, sqlite, or a spreadsheet without python-threatexchange installed *at a compatible version*. This matters most for someone whose actual goal is slicing the data.
- **Fragile across versions.** Renaming a field requires hand-written `__setstate__` shims (two exist already). A class move breaks old files. The documented recovery is `tx fetch --clear`, which is another 7-hour download.
- **Unsafe to share.** Loading a pickle executes code, so a state file from someone else is a code-execution vector. This matters if members start passing datasets around.
- **Not the downside you might expect:** pickle is *compact*. 229 MB versus 575 MB for my naive SQLite layout [measured].

**What a replacement involves** [estimate]:

- SQLite (stdlib, no new dependency) behind the existing `FetchedStateStoreBase` / `SimpleFetchedStateStore` interface
- per-page upserts
- SQL-backed filtering for `dataset`
- a one-time migration from pickle
- about 1–2 weeks including migration and tests

It removes the memory ceiling and makes the data directly queryable by other tools. That would make most of (d) a thin SQL layer.

**Recommendation: not now.** Fix the reload and GC issue first. It's small and removes about 90% of the *speed* pain. Revisit SQLite once issue (d) and Marc's column needs are known: if extra fields have to be stored (finding #6), that is the natural moment to change the storage format rather than add another pickle shim.

### Draft issue (c): Stop reloading fetched state

> **Title:** `[pytx] tx dataset / post-fetch index rebuild unpickle fetched state once per signal type`
>
> `FetchedStateStore.get_for_api()` constructs a fresh `CliSimpleState` per call, and `DatasetCommand.get_signals()` calls it per signal type. So each unfiltered `dataset`, and the index rebuild after every `tx fetch`, unpickles each collab 7× and keeps all copies alive. Measured on 1.4M synthetic Meta TE records: 113s and 4.4 GB, versus 9.4s and 2.5 GB when the store is cached and GC is paused during `pickle.load`. Fix: cache stores per API in `CLISettings`, and wrap `pickle.load` in `gc.disable()/enable()`. Benchmarks: `poc/meta_tx_download/bench_storage.py`.

---

## Where this contradicts the request's assumptions

1. **"Parallelize → 7 h to 30 min."** Parallelizing is technically possible, but the 14× assumes Meta serves many concurrent heavy queries with no throttling. Meta's own docs say the slowness is server-side nested-field resolution, and Graph API throttling meters CPU time per app. The PoC reaches 14× in *no* configuration, even on an unthrottled mock; the best was 12× with 32 streams. Under any cap, the speedup is the cap, and oversubscribing makes it worse. Meta's documented speedup is a *different* technique (two-phase fetch). Treat 30 minutes as unverified.
2. **"Some opportunity to harden with error handling and retries."** It's more specific and more urgent than that: **retries and timeouts are completely inactive** because of a one-line bug that has been live since 2021. On the other hand, a mid-download failure does *not* lose progress; the run resumes from its checkpoint. The real costs are unattended runs stopping early and runs that can hang forever.
3. **"The pickle storage is slow."** Mostly it's that the CLI loads the pickle 7× and GC thrashes during each load, which is fixable in a few lines (12× faster at 1.4M records). Pickle's real problems are memory, opacity, version fragility, and safety, not raw speed. It is also *smaller* on disk than a naive SQLite layout.
4. **"The oldest code might benefit from a v2."** The urgent issue in the old client is not its age but a **hard deadline**: Graph API v21.0 expires 2027-01-21, about 4 months from now, and that also breaks HMA's ThreatExchange fetcher.
5. **"More slicing options."** Some of what Marc may want is not a CLI-options problem. `last_updated`, `added_on`, description, and similar fields are **discarded at fetch time**, so no filter flag can expose them.

## End-to-end validation: what access is needed

- **A Meta ThreatExchange app access token** (`<app_id>|<secret>`, via `TX_ACCESS_TOKEN`) whose app is a **member of a privacy group of realistic size.** Ideally that's Marc's group, or a ROOST-owned test group seeded with at least 100K indicators; a tiny group can't reveal throttling.
- **A 15-minute probe** (not built yet; it's a small script on top of `parallel_fetch.py`):
  - For `limit` ∈ {100, 500, 1000} and concurrency ∈ {1, 2, 4, 8, 16}, fetch time-sharded pages for about 60–90 s each.
  - Log per-request latency, records/page, HTTP status and `error.code`, and the `X-App-Usage` / `X-Business-Use-Case-Usage` headers.
  - This answers the per-request vs per-record cost split, the concurrency ceiling, and how throttling actually looks. It should run with the privacy group owner's consent, since it spends the app's quota.
- **Marc's list of desired filters and columns**, plus the approximate size of his privacy group and how often he'll fetch (relevant to the 85-day re-download cliff).
- Lantern data itself isn't needed; any group with similar volume and type mix will do.

## Reproducing

See `README.md` in this directory. Results from my runs are in `results/fetch.json` and `results/storage.json`.

Environment: Python 3.12.14, 8 CPUs, 14 GB RAM, Linux.
