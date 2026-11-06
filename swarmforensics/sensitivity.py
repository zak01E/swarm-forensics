"""Robustness checks: similarity threshold sweep, and staged-loader census.

Usage: python -m swarmforensics.sensitivity <redacted.jsonl.gz> <out_dir>
"""
import json
import os
import random
import re
import sys
from collections import Counter

from .load import load, artifacts
from .style import doc_skeleton, families
from .analyze import pair_share, SECRET_TYPES, log

LOADER = re.compile(r"<script src=[^>]*SHORTENER|urlopen\('\[SHORTENER|n\('(//)?\[SHORTENER|\[SHORTENER CODE \d+\]")


def main(path, out):
    rng = random.Random(11)
    rows, docs = load(path)
    n = len(docs)
    skels = [doc_skeleton(d) for d in docs]
    uniq = sorted(set(skels))
    sidx = {s: i for i, s in enumerate(uniq)}
    skel_id = [sidx[s] for s in skels]
    full = ["\n".join([d["text"]] + d["child_texts"]) for d in docs]
    doc_arts = [artifacts(t) for t in full]
    res = {"threshold_sweep": []}
    for thr in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        roots, _ = families(uniq, threshold=thr, seed=0)
        fam = [roots[skel_id[i]] for i in range(n)]
        sz = Counter(fam)
        v = pair_share(doc_arts, fam, skel_id, rng, 50000, SECRET_TYPES)
        res["threshold_sweep"].append({
            "threshold": thr, "families": len(sz), "largest_family": max(sz.values()),
            "docs_in_groups_of_2plus": sum(c for c in sz.values() if c >= 2),
            "same_secret_share": v["same_share"], "cross_secret_share": v["cross_share"], "lift": v["lift"]})
        log("thr", thr, len(sz), v["lift"])

    # Staged loaders: payloads that pull further code through URL shorteners.
    loader_docs = [i for i in range(n) if LOADER.search(full[i])]
    short_urls = Counter(a for i in loader_docs for a in doc_arts[i] if a.startswith("[SHORTENER URL"))
    codes = Counter(m for i in loader_docs for m in re.findall(r"\[SHORTENER CODE \d+\]", full[i]))
    res["staged_loaders"] = {
        "docs": len(loader_docs), "share_of_docs": len(loader_docs) / n,
        "distinct_shortener_urls": len(short_urls), "distinct_shortener_codes": len(codes),
        "shortener_codes_seen_in_2plus_docs": sum(1 for c in codes.values() if c >= 2),
        "kinds": dict(Counter(docs[i]["kind"] for i in loader_docs)),
    }
    with open(os.path.join(out, "sensitivity.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
