# Copyright (c) Meta Platforms, Inc. and affiliates.

"""
Synthetic records shaped like Meta ThreatExchange /threat_updates responses.

This mirrors the JSON shape that the `tx` CLI requests via
FBThreatExchangeIndicatorRecord.te_threat_updates_fields():

    indicator,type,last_updated,should_delete,
    descriptors{id,reactions,owner{id},tags,status}

Everything about the *distribution* (type mix, owners, tags, timestamps,
burstiness) is invented. We have no real privacy group data, so treat it as
"plausible", not "representative".
"""

import random
import typing as t

# Weighted mix of ThreatExchange indicator types. The last few have no
# SignalType mapping in python-threatexchange, so the CLI stores them but
# `dataset` never shows them.
TYPE_WEIGHTS = [
    ("HASH_PDQ", 70),
    ("HASH_MD5", 8),  # only mapped to video_md5 when tagged media_type_video
    ("HASH_VIDEO_MD5", 6),
    ("URI", 5),
    ("TEXT_STRING", 3),
    ("HASH_TMK", 4),  # no SignalType mapping
    ("HASH_SHA1", 4),  # no SignalType mapping
]
TAGS = [
    "media_type_photo",
    "media_type_video",
    "csam",
    "terrorism",
    "ncii",
    "sextortion",
    "hate",
    "violent_extremism",
    "lantern_program_x",
    "confirmed",
]
STATUSES = [("MALICIOUS", 70), ("UNKNOWN", 25), ("NON_MALICIOUS", 5)]
OWNER_APPS = [1000000000000 + i for i in range(40)]
MY_APP_ID = OWNER_APPS[0]

START_TS = 1_600_000_000  # 2020-09
END_TS = 1_790_000_000  # 2026-09


def _weighted(rng: random.Random, pairs: t.Sequence[t.Tuple[str, int]]) -> str:
    return rng.choices([p[0] for p in pairs], weights=[p[1] for p in pairs])[0]


def _indicator(rng: random.Random, ty: str) -> str:
    if ty == "HASH_PDQ":
        return "%064x" % rng.getrandbits(256)
    if ty in ("HASH_MD5", "HASH_VIDEO_MD5"):
        return "%032x" % rng.getrandbits(128)
    if ty == "HASH_SHA1":
        return "%040x" % rng.getrandbits(160)
    if ty == "HASH_TMK":
        return "tmk:" + "%0256x" % rng.getrandbits(1024)
    if ty == "URI":
        return f"https://example.com/{rng.getrandbits(48):x}"
    return f"some bad text {rng.getrandbits(32):x}"


def _timestamp(rng: random.Random, bursts: t.List[int]) -> int:
    # ~35% of records land in a bulk-upload burst (many records sharing a
    # handful of seconds). The rest grow roughly linearly over time
    # (sqrt => density increases towards the present).
    if rng.random() < 0.35:
        return rng.choice(bursts) + rng.randrange(5)
    return START_TS + int((END_TS - START_TS) * (rng.random() ** 0.5))


def generate(n: int, seed: int = 1234, delete_frac: float = 0.03) -> t.List[dict]:
    """
    Return n update records sorted the way /threat_updates returns them:
    ascending last_updated (ties broken by id).
    """
    ret = list(iter_records(n, seed, delete_frac))
    ret.sort(key=lambda r: (r["last_updated"], int(r["id"])))
    return ret


def iter_records(
    n: int, seed: int = 1234, delete_frac: float = 0.03
) -> t.Iterator[dict]:
    """Unsorted, streaming version of generate() for large storage benchmarks"""
    rng = random.Random(seed)
    bursts = [
        START_TS + int((END_TS - START_TS) * rng.random() ** 0.5) for _ in range(20)
    ]
    for i in range(n):
        ty = _weighted(rng, TYPE_WEIGHTS)
        rec: t.Dict[str, t.Any] = {
            "id": str(3_000_000_000_000_000 + i),
            "indicator": _indicator(rng, ty),
            "type": ty,
            "last_updated": _timestamp(rng, bursts),
            "should_delete": rng.random() < delete_frac,
        }
        if not rec["should_delete"]:
            descriptors = []
            for owner in rng.sample(OWNER_APPS, k=rng.choice([1, 1, 1, 2, 3])):
                tags = rng.sample(TAGS, k=rng.randrange(0, 4))
                if ty == "HASH_MD5" and rng.random() < 0.5:
                    tags.append("media_type_video")
                d: t.Dict[str, t.Any] = {
                    "id": str(rng.getrandbits(53)),
                    "owner": {"id": str(owner)},
                    "status": _weighted(rng, STATUSES),
                    "tags": {
                        "data": [
                            {"id": str(abs(hash(tg)) % 10**12), "text": tg}
                            for tg in sorted(set(tags))
                        ]
                    },
                }
                if rng.random() < 0.1:
                    d["reactions"] = [
                        {
                            "key": rng.choice(["HELPFUL", "DISAGREE_WITH_TAGS"]),
                            "value": ",".join(
                                str(o) for o in rng.sample(OWNER_APPS, k=2)
                            ),
                        }
                    ]
                descriptors.append(d)
            rec["descriptors"] = {"data": descriptors}
        yield rec
