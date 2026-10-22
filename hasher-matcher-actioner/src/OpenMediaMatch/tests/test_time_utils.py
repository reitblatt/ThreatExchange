# Copyright (c) Meta Platforms, Inc. and affiliates.

from OpenMediaMatch.utils.time_utils import time_ranges_to_human_str


def test_time_ranges_to_human_str():
    assert (
        time_ranges_to_human_str([(0, 600)])
        == "1970-01-01 00:00:00 - 1970-01-01 00:10:00 UTC"
    )
    assert time_ranges_to_human_str([(0, 1), (2, 3), (4, 5), (6, 7)], max_shown=2) == (
        "1970-01-01 00:00:00 - 1970-01-01 00:00:01 UTC, "
        "1970-01-01 00:00:02 - 1970-01-01 00:00:03 UTC, and 2 more"
    )
