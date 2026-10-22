# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Helpers for duration and times
"""

import datetime
import typing as t

from dateutil.relativedelta import relativedelta


def duration_to_human_str(sec: float, *, terse: bool = False) -> str:
    """
    Convert a span of time into a simple human string.

    Examples:

      15 -> 15s
    """

    if sec < 0.001:
        return "0 seconds"

    if sec < 1:
        ms = sec * 1000
        suffix = "ms" if terse else "milliseconds"
        ms_str = f"{ms:.1f}" if ms < 10 else f"{ms:.0f}"
        return f"{ms_str} {suffix}"

    delta = relativedelta(seconds=int(sec))

    if delta.years > 0:
        return "More than a year"

    parts: list[str] = []

    durations = [
        (" months", delta.months),
        (" days", delta.days),
        (" hours", delta.hours),
        (" minutes", delta.minutes),
        (" seconds", delta.seconds),
    ]

    for i, (label, val) in enumerate(durations):
        if terse:
            label = label[1]
        elif val == 1:
            label = label[:-1]
        final = bool(parts)
        if val > 0 or (i == len(durations) - 1 and not final):
            parts.append(f"{val}{label}")
        if final:
            break

    return " ".join(parts)


def time_ranges_to_human_str(
    ranges: t.Sequence[t.Tuple[int, int]], *, max_shown: int = 3
) -> str:
    """
    Convert [start, end) unix time ranges into a simple human string, in UTC.

    Examples:

      [(0, 600)] -> 1970-01-01 00:00:00 - 1970-01-01 00:10:00 UTC
    """

    def fmt(ts: int) -> str:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    shown = ", ".join(
        f"{fmt(start)} - {fmt(end)} UTC" for start, end in ranges[:max_shown]
    )
    if len(ranges) > max_shown:
        shown += f", and {len(ranges) - max_shown} more"
    return shown
