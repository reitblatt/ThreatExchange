# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
PoC: time-sharded parallel download of Meta ThreatExchange /threat_updates.

Drop-in replacement for FBThreatExchangeSignalExchangeAPI.fetch_iter():
it yields the same ThreatExchangeDelta objects, in the same (time) order, with
checkpoints that are safe to resume from. The stock FetchCommand / CliSimpleState
can consume it unchanged.

How it works
  1. Probe for the earliest last_updated >= the checkpoint (1 tiny request).
  2. Cut [earliest, now) into workers * shards_per_worker equal time ranges.
     The last shard is open-ended (no stop_time), exactly like the serial fetch.
     /threat_updates supports start_time (inclusive) + stop_time (exclusive),
     so shards are disjoint and their union is the serial result.
  3. A thread pool pulls shards off a queue. Over-partitioning (many more
     shards than workers) is what absorbs skew: real data is bursty in time,
     so equal time ranges are very unequal in record count.
  4. Shards are *yielded* strictly in time order. The fetch store merges
     last-write-wins by key, so applying in time order gives the same final
     state as the serial fetch, including tombstones.
  5. The checkpoint only advances past a shard once it and every earlier shard
     are complete. On failure, everything before the failed shard has been
     yielded (and so is persisted by FetchCommand's finally: flush()), and a
     re-run resumes from there.

Hardening that the stock client lacks (see REPORT.md, "a2"):
  * a real requests.Session: keep-alive + a pooled connection per worker
  * connect/read timeouts (stock GETs have none, and can hang forever)
  * retries with exponential backoff + jitter on connection errors, timeouts,
    HTTP 5xx/429, and Graph throttling error codes (4, 17, 32, 613)
  * a shared "cool-down" so one throttled worker pauses all of them rather
    than N workers hammering a rate-limited app

Not production-ready: completed-but-not-yet-yielded shards are buffered in
memory, and there's no adaptive re-splitting of a hot shard.
"""

import logging
import random
import threading
import time
import typing as t
from concurrent.futures import Future, ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter

from threatexchange.exchanges.clients.fb_threatexchange.threat_updates import (
    ThreatUpdateJSON,
)
from threatexchange.exchanges.impl.fb_threatexchange_api import (
    FBThreatExchangeCheckpoint,
    FBThreatExchangeIndicatorRecord,
    FBThreatExchangeSignalExchangeAPI,
    ThreatExchangeDelta,
    _make_indicator_type_mapping,
)
from threatexchange.signal_type.signal_base import SignalType

log = logging.getLogger(__name__)

# Graph API error codes that mean "back off and try again"
# https://developers.facebook.com/docs/graph-api/overview/rate-limiting/
# 1/2 are the generic "unknown/temporary" API errors.
_RETRYABLE_GRAPH_CODES = {1, 2, 4, 17, 32, 613}


class GraphRequestError(Exception):
    pass


class RetryingGraphClient:
    def __init__(
        self,
        *,
        pool_size: int = 16,
        connect_timeout: float = 10.0,
        read_timeout: float = 120.0,
        max_attempts: int = 8,
        backoff_base: float = 1.0,
        backoff_max: float = 120.0,
        max_throttle_wait_sec: float = 3600.0,
        sleep: t.Callable[[float], None] = time.sleep,
    ) -> None:
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=pool_size)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.timeout = (connect_timeout, read_timeout)
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.max_throttle_wait_sec = max_throttle_wait_sec
        self._sleep = sleep
        self._cooldown_until = 0.0
        self._lock = threading.Lock()
        self.stats = {"requests": 0, "retries": 0, "throttled": 0}

    def close(self) -> None:
        self.session.close()

    def _wait_for_cooldown(self) -> None:
        delay = self._cooldown_until - time.monotonic()
        if delay > 0:
            self._sleep(delay)

    def _backoff(self, attempt: int, shared: bool) -> float:
        delay = min(self.backoff_max, self.backoff_base * 2**attempt)
        delay *= 0.5 + random.random()  # jitter
        if shared:
            with self._lock:
                self._cooldown_until = max(
                    self._cooldown_until, time.monotonic() + delay
                )
        self._sleep(delay)
        return delay

    def get_json(
        self, url: str, params: t.Optional[t.Dict[str, t.Any]] = None
    ) -> t.Dict[str, t.Any]:
        """
        Two separate budgets:
          * errors (network, timeouts, 5xx): max_attempts, then give up
          * throttling: Graph limits are rolling *hourly* windows, so a small
            attempt count is the wrong unit. Keep backing off (shared across
            workers) until max_throttle_wait_sec of cumulative waiting.
        """
        last_err: t.Optional[BaseException] = None
        errors = 0
        throttles = 0
        throttle_waited = 0.0
        while True:
            self._wait_for_cooldown()
            with self._lock:
                self.stats["requests"] += 1
                if errors or throttles:
                    self.stats["retries"] += 1
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except (requests.ConnectionError, requests.Timeout) as e:
                last_err = e
                log.warning("GET failed (%s), attempt %d", type(e).__name__, errors)
                resp = None
            if resp is not None and resp.status_code == 200:
                return resp.json()
            code = None
            if resp is not None:
                try:
                    code = resp.json().get("error", {}).get("code")
                except ValueError:
                    pass
                if resp.status_code == 429 or code in (4, 17, 32, 613):
                    with self._lock:
                        self.stats["throttled"] += 1
                    if throttle_waited >= self.max_throttle_wait_sec:
                        raise GraphRequestError(
                            f"still throttled after {throttle_waited:.0f}s"
                        )
                    throttle_waited += self._backoff(throttles, shared=True)
                    throttles += 1
                    continue
                if resp.status_code < 500 and code not in _RETRYABLE_GRAPH_CODES:
                    # 4xx that isn't throttling (bad token, bad field...)
                    raise GraphRequestError(
                        f"HTTP {resp.status_code} code={code}: {resp.text[:300]}"
                    )
                last_err = GraphRequestError(f"HTTP {resp.status_code} code={code}")
            errors += 1
            if errors >= self.max_attempts:
                raise GraphRequestError(
                    f"gave up after {errors} failed attempts"
                ) from last_err
            self._backoff(errors - 1, shared=False)


class ParallelFBThreatExchangeSignalExchangeAPI(FBThreatExchangeSignalExchangeAPI):
    workers: int = 8
    shards_per_worker: int = 8
    page_size: int = 500
    # Only request ThreatExchange types we have a SignalType for. Off by
    # default because the stock CLI stores everything.
    only_supported_types: bool = False
    graph: t.Optional[RetryingGraphClient] = None

    def _graph(self) -> RetryingGraphClient:
        if self.graph is None:
            self.graph = RetryingGraphClient(pool_size=self.workers)
        return self.graph

    def _base_params(self, types: t.Sequence[str]) -> t.Dict[str, t.Any]:
        params: t.Dict[str, t.Any] = {
            "access_token": self.client.api_token,
            "fields": ",".join(ThreatUpdateJSON.te_threat_updates_fields()),
        }
        if types:
            params["types"] = ",".join(types)
        return params

    def _url(self) -> str:
        return f"{self.client._base_url}/{self.collab.privacy_group}/threat_updates/"

    def _fetch_shard(
        self, start: int, stop: t.Optional[int], types: t.Sequence[str]
    ) -> t.List[t.List[ThreatUpdateJSON]]:
        graph = self._graph()
        params = self._base_params(types)
        params.update(start_time=start, limit=self.page_size)
        if stop is not None:
            params["stop_time"] = stop
        pages = []
        resp = graph.get_json(self._url(), params)
        while True:
            data = [ThreatUpdateJSON(x) for x in resp.get("data", [])]
            if data:
                pages.append(data)
            nxt = resp.get("paging", {}).get("next")
            if not nxt:
                return pages
            resp = graph.get_json(nxt)  # next URL carries all params

    def _earliest(self, start: int, types: t.Sequence[str]) -> t.Optional[int]:
        params = self._base_params(types)
        params.update(start_time=start, limit=1, fields="id,last_updated")
        data = self._graph().get_json(self._url(), params).get("data", [])
        return int(data[0]["last_updated"]) if data else None

    def fetch_iter(
        self,
        supported_signal_types: t.Sequence[t.Type[SignalType]],
        checkpoint: t.Optional[FBThreatExchangeCheckpoint],
    ) -> t.Iterator[ThreatExchangeDelta]:
        types: t.Sequence[str] = ()
        if self.only_supported_types:
            types = sorted(_make_indicator_type_mapping(supported_signal_types))
        start = 0 if checkpoint is None else checkpoint.update_time
        now = int(time.time())
        earliest = self._earliest(start, types)
        if earliest is None:
            return
        n = max(1, self.workers * self.shards_per_worker)
        width = max(1, (now - earliest) // n)
        bounds = [earliest + i * width for i in range(n)] + [None]
        bounds[0] = start  # don't skip anything between checkpoint and earliest
        shards = [(bounds[i], bounds[i + 1]) for i in range(n)]

        highest = start
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures: t.List[Future] = [
                pool.submit(self._fetch_shard, s, e, types) for s, e in shards
            ]
            try:
                for (s, e), fut in zip(shards, futures):
                    pages = fut.result()  # re-raises shard failure
                    for i, batch in enumerate(pages):
                        highest = max(highest, max(u.time for u in batch))
                        cp_time = highest
                        if e is not None and i == len(pages) - 1:
                            # Everything < e is now fetched
                            cp_time = highest = max(highest, e)
                        updates = {
                            (u.threat_type, u.indicator): (
                                FBThreatExchangeIndicatorRecord.from_threatexchange_json(
                                    self.client.app_id, u
                                )
                            )
                            for u in batch
                        }
                        yield ThreatExchangeDelta(
                            updates, FBThreatExchangeCheckpoint(cp_time)
                        )
            finally:
                for f in futures:
                    f.cancel()
        if self.graph is not None:
            self.graph.close()
