# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
PoC for the requester's step 2+3: filter already-fetched ThreatExchange data
and write a CSV with chosen columns.

Reads the same state `tx fetch` writes (TX_STATEDIR, default ~/.threatexchange),
read-only, loading each collab's state file once.

    # every PDQ with a csam tag that at least 2 apps have an opinion on,
    # one row per opinion, with owner + descriptor ids
    python poc/meta_tx_download/export_csv.py \\
        --te-type HASH_PDQ --tag-any csam --min-owners 2 \\
        --rows opinion \\
        --columns indicator,owner_app_id,descriptor_id,opinion_category,opinion_tags

Semantics: every filter flag is ANDed; the values within one flag are ORed
(except --tag-all). In `--rows indicator` mode, owner/category/tag filters
select indicators with at least one matching opinion; in `--rows opinion` mode
they select the opinions themselves.

This is a sketch of the flags proposed for `tx dataset` in REPORT.md, not a
replacement for it.
"""

import argparse
import csv
import os
import pathlib
import sys
import typing as t

from threatexchange.cli.main import CliState, _get_settings
from threatexchange.exchanges.fetch_state import (
    AggregateSignalOpinion,
    SignalOpinion,
    SignalOpinionCategory,
)
from threatexchange.exchanges.impl.fb_threatexchange_api import (
    _make_indicator_type_mapping,
)

INDICATOR_COLUMNS = {
    "collab": "collaboration name",
    "te_type": "ThreatExchange indicator type, e.g. HASH_PDQ",
    "signal_type": "python-threatexchange SignalType(s) this maps to, if any",
    "indicator": "the hash / URL / string",
    "category": "aggregate opinion (POSITIVE_CLASS, DISPUTED, ...)",
    "tags": "union of tags across opinions",
    "owners": "app ids with an opinion",
    "n_owners": "number of distinct app ids with an opinion",
}
OPINION_COLUMNS = {
    "owner_app_id": "[--rows opinion] app id that owns this opinion",
    "descriptor_id": "[--rows opinion] ThreatDescriptor id (-1 = reaction only)",
    "opinion_category": "[--rows opinion] this opinion's category",
    "opinion_tags": "[--rows opinion] this opinion's tags",
    "is_mine": "[--rows opinion] opinion belongs to the token's app",
}
DEFAULT_COLUMNS = "collab,te_type,indicator,category,tags"
# Stored by `tx fetch` today: only the above. NOT stored (dropped at fetch
# time), so impossible to export without changing the fetch/storage layer:
# last_updated, added_on, description, confidence, severity, share_level,
# review_status, indicator/descriptor creation time.


def _csv_list(s: str) -> t.List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def get_argparse() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--state-dir", default=os.getenv("TX_STATEDIR", "~/.threatexchange")
    )
    ap.add_argument("--collab", nargs="+", default=[], help="collab name(s)")
    ap.add_argument("--te-type", nargs="+", default=[], help="e.g. HASH_PDQ")
    ap.add_argument("--signal-type", nargs="+", default=[], help="e.g. pdq")
    ap.add_argument("--tag-any", nargs="+", default=[])
    ap.add_argument("--tag-all", nargs="+", default=[])
    ap.add_argument("--tag-none", nargs="+", default=[])
    ap.add_argument(
        "--category",
        nargs="+",
        default=[],
        choices=[c.name for c in SignalOpinionCategory],
        help="opinion category",
    )
    ap.add_argument("--owner", nargs="+", type=int, default=[], help="app id(s)")
    ap.add_argument("--exclude-owner", nargs="+", type=int, default=[])
    ap.add_argument("--min-owners", type=int, default=0)
    ap.add_argument("--rows", choices=["indicator", "opinion"], default="indicator")
    ap.add_argument("--columns", type=_csv_list, default=_csv_list(DEFAULT_COLUMNS))
    ap.add_argument("--list-columns", action="store_true")
    ap.add_argument("-o", "--output", default="-")
    return ap


class Exporter:
    def __init__(self, a: argparse.Namespace) -> None:
        self.a = a
        allowed = dict(INDICATOR_COLUMNS)
        if a.rows == "opinion":
            allowed.update(OPINION_COLUMNS)
        bad = [c for c in a.columns if c not in allowed]
        if bad:
            raise SystemExit(
                f"unknown column(s) for --rows {a.rows}: {bad}. Try --list-columns"
            )

    def opinion_ok(self, o: SignalOpinion) -> bool:
        a = self.a
        owner = getattr(o, "owner_app_id", None)
        if a.owner and owner not in a.owner:
            return False
        if a.exclude_owner and owner in a.exclude_owner:
            return False
        if a.category and o.category.name not in a.category:
            return False
        if a.tag_any and not (o.tags & set(a.tag_any)):
            return False
        return True

    def rows(
        self,
        collab: str,
        te_type: str,
        indicator: str,
        opinions: t.Sequence[SignalOpinion],
        signal_types: str,
    ) -> t.Iterator[t.Dict[str, t.Any]]:
        a = self.a
        all_tags = {tag for o in opinions for tag in o.tags}
        if a.tag_all and not set(a.tag_all) <= all_tags:
            return
        if a.tag_none and all_tags & set(a.tag_none):
            return
        owners = sorted({getattr(o, "owner_app_id", "") for o in opinions} - {""})
        if a.min_owners and len(owners) < a.min_owners:
            return
        matching = [o for o in opinions if self.opinion_ok(o)]
        if not matching:
            return
        base = {
            "collab": collab,
            "te_type": te_type,
            "signal_type": signal_types,
            "indicator": indicator,
            "owners": " ".join(str(x) for x in owners),
            "n_owners": len(owners),
        }
        agg = AggregateSignalOpinion.from_opinions(list(opinions))
        base["category"] = agg.category.name
        base["tags"] = " ".join(sorted(agg.tags))
        if a.rows == "indicator":
            yield base
            return
        for o in matching:
            row = dict(base)
            row.update(
                owner_app_id=getattr(o, "owner_app_id", ""),
                descriptor_id=getattr(o, "descriptor_id", ""),
                opinion_category=o.category.name,
                opinion_tags=" ".join(sorted(o.tags)),
                is_mine=int(o.is_mine),
            )
            yield row

    def run(self, out: t.TextIO) -> int:
        a = self.a
        state_dir = pathlib.Path(a.state_dir).expanduser()
        settings, _ = _get_settings(
            CliState([], state_dir).get_persistent_config(), state_dir
        )
        mapping = _make_indicator_type_mapping(settings.get_all_signal_types())
        collabs = settings.get_all_collabs(default_to_sample=False)
        if a.collab:
            collabs = [c for c in collabs if c.name in a.collab]
        writer = csv.DictWriter(out, a.columns, extrasaction="ignore")
        writer.writeheader()
        n = 0
        for collab in collabs:
            store = settings.fetched_state.get_for_collab(collab)
            delta = store._read_state(collab.name)  # one pickle load
            if delta is None:
                continue
            for key, record in delta.updates.items():
                if record is None:
                    continue
                if isinstance(key, tuple) and len(key) == 2:
                    te_type, indicator = key
                else:  # non-ThreatExchange collab
                    te_type, indicator = "", str(key)
                if a.te_type and te_type not in a.te_type:
                    continue
                opinions = list(record.get_as_opinions())
                tags = {tag for o in opinions for tag in o.tags}
                sts = sorted(
                    st.get_name()
                    for tag, st_list in mapping.get(te_type, {}).items()
                    if tag is None or tag in tags
                    for st in st_list
                )
                if a.signal_type and not set(a.signal_type) & set(sts):
                    continue
                for row in self.rows(
                    collab.name, te_type, indicator, opinions, " ".join(sts)
                ):
                    writer.writerow(row)
                    n += 1
        return n


def main(argv: t.Optional[t.Sequence[str]] = None) -> None:
    a = get_argparse().parse_args(argv)
    if a.list_columns:
        for name, desc in {**INDICATOR_COLUMNS, **OPINION_COLUMNS}.items():
            print(f"{name:18} {desc}")
        return
    exporter = Exporter(a)
    if a.output == "-":
        n = exporter.run(sys.stdout)
    else:
        with open(a.output, "w", newline="") as fh:
            n = exporter.run(fh)
    print(f"wrote {n} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
