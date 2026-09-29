# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Tests that the CLI loads fetched state from disk once, and does it cheaply.

Before the store was shared, `dataset` unpickled every collaboration once per
signal type, which took minutes and gigabytes on large datasets.
"""

import gc
import io
import pickle
import typing as t

import pytest

from threatexchange.cli.cli_state import _load_pickle
from threatexchange.cli.tests.e2e_test_helper import (
    ThreatExchangeCLIE2eHelper,
    te_cli,  # noqa: F401 - pytest fixture
)


@pytest.fixture
def pickle_loads(monkeypatch: pytest.MonkeyPatch) -> t.List[int]:
    """One entry appended per pickle.load() call"""
    calls: t.List[int] = []
    real_load = pickle.load

    def counting_load(*args: t.Any, **kwargs: t.Any) -> t.Any:
        calls.append(1)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(pickle, "load", counting_load)
    return calls


def test_dataset_loads_state_once(
    te_cli: ThreatExchangeCLIE2eHelper, pickle_loads: t.List[int]  # noqa: F811
):
    te_cli.cli_call("fetch", "--skip-index-rebuild")
    del pickle_loads[:]

    # Summary, listing, and index rebuild all look at every signal type
    te_cli.cli_call("dataset")
    assert len(pickle_loads) == 1
    del pickle_loads[:]
    te_cli.cli_call("dataset", "-P", "--csv")
    assert len(pickle_loads) == 1
    del pickle_loads[:]
    te_cli.cli_call("dataset", "--rebuild-indices")
    assert len(pickle_loads) == 1


def test_fetch_index_rebuild_reuses_fetched_state(
    te_cli: ThreatExchangeCLIE2eHelper, pickle_loads: t.List[int]  # noqa: F811
):
    # Nothing on disk to load, and the rebuild afterwards should use what
    # fetch just merged rather than reading the file back
    te_cli.cli_call("fetch")
    assert pickle_loads == []
    assert "url: 1" in te_cli.cli_call("dataset", "-s", "url")


class _RecordsGcState:
    """Unpickling this records whether the garbage collector was running"""

    seen: t.List[bool] = []
    value = 0

    def __setstate__(self, state: t.Any) -> None:
        self.seen.append(gc.isenabled())


def _dump_recorder() -> bytes:
    obj = _RecordsGcState()
    obj.value = 1  # Empty instance state isn't passed to __setstate__
    return pickle.dumps(obj)


def test_load_pickle_pauses_gc_and_restores_it():
    data = _dump_recorder()
    _RecordsGcState.seen = []
    assert gc.isenabled()
    _load_pickle(io.BytesIO(data))
    assert _RecordsGcState.seen == [False]
    assert gc.isenabled()


def test_load_pickle_leaves_gc_disabled_if_it_was():
    data = _dump_recorder()
    gc.disable()
    try:
        _load_pickle(io.BytesIO(data))
        assert not gc.isenabled()
    finally:
        gc.enable()


def test_load_pickle_restores_gc_on_error():
    assert gc.isenabled()
    with pytest.raises(pickle.UnpicklingError):
        _load_pickle(io.BytesIO(b"not a pickle"))
    assert gc.isenabled()
