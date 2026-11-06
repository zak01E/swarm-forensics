"""Full pipeline: families -> artifact graph -> coordination signals -> validation.

Usage: python -m swarmforensics.analyze <redacted.jsonl.gz> <out_dir>
"""
import json
import math
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict

import numpy as np

from .load import load, artifacts, artifact_type
from .style import doc_skeleton, families, traits, MinHasher, shingles

SECRET_TYPES = {"CREDENTIAL", "R:secret_key", "R:bearer_token", "R:aws_auth_value", "ENV VALUE"}
UA = re.compile(r"User-Agent['\"]?\s*[:,]\s*['\"]([^'\"\[]{2,80})['\"]", re.I)
GENERIC_UA = re.compile(r"^(Mozilla|curl|python|node|axios|Go-http|Wget)", re.I)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def group_docs(labels):
    g = defaultdict(list)
    for i, l in enumerate(labels):
        g[l].append(i)
    return g


def pair_share(doc_arts, labels, skel_id, rng, n_pairs, mask_types=None, distinct_skel=True):
    """P(two docs share >= 1 artifact) for same-group pairs vs cross-group pairs."""
    def arts(i):
        a = doc_arts[i]
        if mask_types is not None:
            a = {x for x in a if artifact_type(x) in mask_types}
        return a

    groups = [m for m in group_docs(labels).values() if len(m) >= 2]
    weights = [len(m) for m in groups]
    n = len(labels)
    same_k = same_n = 0
    tries = 0
    while same_n < n_pairs and tries < n_pairs * 20:
        tries += 1
        m = rng.choices(groups, weights)[0]
        i, j = rng.sample(m, 2)
        if distinct_skel and skel_id[i] == skel_id[j]:
            continue
        same_n += 1
        same_k += bool(arts(i) & arts(j))
    cross_k = cross_n = 0
    while cross_n < n_pairs:
        i, j = rng.randrange(n), rng.randrange(n)
        if labels[i] == labels[j]:
            continue
        cross_n += 1
        cross_k += bool(arts(i) & arts(j))
    s, c = wilson(same_k, same_n), wilson(cross_k, cross_n)
    return {"same_pairs": same_n, "same_share": s, "cross_pairs": cross_n, "cross_share": c,
            "lift": (s[0] / c[0]) if c[0] > 0 else None}


def main(path, out):
    os.makedirs(out, exist_ok=True)
    rng = random.Random(7)
    log("loading")
    rows, docs = load(path)
    n = len(docs)
    log("docs", n)

    skels = [doc_skeleton(d) for d in docs]
    uniq = sorted(set(skels))
    sidx = {s: i for i, s in enumerate(uniq)}
    skel_id = [sidx[s] for s in skels]
    log("unique skeletons", len(uniq))

    roots, sigs = families(uniq, seed=0)
    raw = [roots[skel_id[i]] for i in range(n)]
    size = Counter(raw)
    rank = {r: k for k, (r, _) in enumerate(size.most_common())}
    fam = [rank[r] for r in raw]
    fam_name = lambda f: f"F{f + 1:05d}"
    log("families", len(size))

    full_text = ["\n".join([d["text"]] + d["child_texts"]) for d in docs]
    doc_arts = [artifacts(t) for t in full_text]

    # ---- artifact index -------------------------------------------------
    art_docs = defaultdict(list)
    for i, a in enumerate(doc_arts):
        for x in a:
            art_docs[x].append(i)
    art_fams = {a: Counter(fam[i] for i in ds) for a, ds in art_docs.items()}
    log("artifacts", len(art_docs))

    # ---- families ---------------------------------------------------------
    members = group_docs(fam)
    fam_rows = []
    for f in sorted(members):
        ds = members[f]
        if len(ds) < 3:
            continue
        sample = ds if len(ds) <= 300 else rng.sample(ds, 300)
        tc = Counter(t for i in sample for t in traits(full_text[i]))
        top_skel = Counter(skel_id[i] for i in ds).most_common(1)[0][0]
        example = next(i for i in ds if skel_id[i] == top_skel)
        ac = Counter(x for i in ds for x in doc_arts[i])
        secrets = [x for x in ac if artifact_type(x) in SECRET_TYPES]
        fam_rows.append({
            "id": fam_name(f), "docs": len(ds), "variants": len({skel_id[i] for i in ds}),
            "kinds": dict(Counter(docs[i]["kind"] for i in ds)),
            "traits": {k: round(v / len(sample), 2) for k, v in tc.most_common() if v / len(sample) >= 0.2},
            "example_id": docs[example]["id"], "example": full_text[example][:900],
            "n_artifacts": len(ac), "n_secrets": len(secrets),
            "top_artifacts": ac.most_common(12),
        })
    log("described families", len(fam_rows))

    # ---- coordination signal 1: artifacts reused across families ------------
    cross = []
    for a, fc in art_fams.items():
        if len(fc) >= 3:
            cross.append({"artifact": a, "type": artifact_type(a), "docs": len(art_docs[a]),
                          "families": len(fc), "top_families": [(fam_name(f), c) for f, c in fc.most_common(8)]})
    cross.sort(key=lambda r: (-r["families"], -r["docs"]))
    by_type = Counter(r["type"] for r in cross)
    secret_cross = [r for r in cross if r["type"] in SECRET_TYPES]
    log("cross-family artifacts", len(cross), "secrets", len(secret_cross))

    # ---- coordination signal 2: family graph through shared secrets ---------
    # Two families are linked when they use the same secret. Secrets used by more
    # than MAX_FAM families are treated as 'public knowledge' and dropped: they
    # were clearly broadcast to everyone and would glue the whole graph together.
    MAX_FAM = 20
    edges = Counter()
    for r in secret_cross:
        if r["families"] > MAX_FAM:
            continue
        fs = sorted(art_fams[r["artifact"]])
        for x in range(len(fs)):
            for y in range(x + 1, len(fs)):
                edges[(fs[x], fs[y])] += 1
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for (x, y) in edges:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)
    comps = defaultdict(set)
    for x in list(parent):
        comps[find(x)].add(x)
    comps = sorted(comps.values(), key=lambda c: -sum(len(members[f]) for f in c))
    comp_secrets = defaultdict(list)
    for r in secret_cross:
        if r["families"] <= MAX_FAM:
            comp_secrets[find(next(iter(art_fams[r["artifact"]])))].append(r["artifact"])
    secret_clusters = [{"families": len(c), "docs": sum(len(members[f]) for f in c),
                        "secrets": comp_secrets[find(next(iter(c)))][:15],
                        "members": [fam_name(f) for f in sorted(c, key=lambda f: -len(members[f]))[:25]]}
                       for c in comps[:40]]
    spread_buckets = {"3-5": 0, "6-20": 0, "21-100": 0, "101+": 0}
    for r in secret_cross:
        k = r["families"]
        spread_buckets["3-5" if k <= 5 else "6-20" if k <= 20 else "21-100" if k <= 100 else "101+"] += 1
    graph_edges = [{"a": fam_name(x), "b": fam_name(y), "shared_secrets": w}
                   for (x, y), w in edges.most_common(400)]
    log("secret graph", len(edges), "edges", len(comps), "components")

    # ---- coordination signal 3: self-chosen names --------------------------
    names = defaultdict(lambda: {"docs": 0, "families": Counter()})
    for i, t in enumerate(full_text):
        for m in UA.findall(t):
            m = m.strip()
            if GENERIC_UA.match(m) or "REDACTED" in m:
                continue
            names[m]["docs"] += 1
            names[m]["families"][fam[i]] += 1
    name_rows = sorted(({"name": k, "docs": v["docs"], "families": len(v["families"]),
                         "top_families": [(fam_name(f), c) for f, c in v["families"].most_common(5)]}
                        for k, v in names.items()), key=lambda r: -r["docs"])
    # Families that carry several different self-chosen names: candidate cases of
    # one coding lineage operating under several identities (track 3).
    fam_names = defaultdict(Counter)
    for k, v in names.items():
        for f, c in v["families"].items():
            fam_names[f][k] += c
    multi_name = sorted(({"family": fam_name(f), "family_docs": len(members[f]), "names": dict(c)}
                         for f, c in fam_names.items() if len(c) >= 2),
                        key=lambda r: -len(r["names"]))
    log("self-chosen names", len(name_rows), "multi-name families", len(multi_name))

    # ---- validation A: do style families predict shared artifacts? ----------
    log("validation A")
    val = {}
    val["style_families_any"] = pair_share(doc_arts, fam, skel_id, rng, 100000)
    val["style_families_secret"] = pair_share(doc_arts, fam, skel_id, rng, 100000, SECRET_TYPES)
    # Baselines: exact skeleton (no fuzzy matching) and trait signature.
    trait_sig = [hash(tuple(traits(t))) for t in full_text]
    val["baseline_traits_secret"] = pair_share(doc_arts, trait_sig, skel_id, rng, 100000, SECRET_TYPES)
    # exact skeleton: same-group pairs always share the skeleton, so allow it.
    val["baseline_exact_secret"] = pair_share(doc_arts, skel_id, skel_id, rng, 100000, SECRET_TYPES,
                                              distinct_skel=False)
    val["style_families_secret_sameskel_allowed"] = pair_share(doc_arts, fam, skel_id, rng, 100000,
                                                               SECRET_TYPES, distinct_skel=False)
    cover = lambda labels: sum(1 for l in labels if Counter(labels)[l] >= 2)  # noqa
    fam_sz, ex_sz, tr_sz = Counter(fam), Counter(skel_id), Counter(trait_sig)
    val["coverage"] = {
        "style_families": {"groups": len(fam_sz), "docs_in_groups_of_2plus": sum(c for c in fam_sz.values() if c >= 2)},
        "exact_skeleton": {"groups": len(ex_sz), "docs_in_groups_of_2plus": sum(c for c in ex_sz.values() if c >= 2)},
        "trait_signature": {"groups": len(tr_sz), "docs_in_groups_of_2plus": sum(c for c in tr_sz.values() if c >= 2)},
        "docs": n,
    }

    # ---- validation B: stability under a different hash seed ---------------
    log("validation B")
    roots1, _ = families(uniq, seed=1)
    fam1 = [roots1[skel_id[i]] for i in range(n)]
    agree = tot = 0
    groups = [m for m in members.values() if len(m) >= 2]
    w = [len(m) for m in groups]
    for _ in range(50000):
        m = rng.choices(groups, w)[0]
        i, j = rng.sample(m, 2)
        tot += 1
        agree += fam1[i] == fam1[j]
    agree_rev = tot_rev = 0
    g1 = [m for m in group_docs(fam1).values() if len(m) >= 2]
    w1 = [len(m) for m in g1]
    for _ in range(50000):
        m = rng.choices(g1, w1)[0]
        i, j = rng.sample(m, 2)
        tot_rev += 1
        agree_rev += fam[i] == fam[j]
    val["seed_stability"] = {"pairs_kept_seed0_to_seed1": wilson(agree, tot),
                             "pairs_kept_seed1_to_seed0": wilson(agree_rev, tot_rev),
                             "families_seed1": len(set(fam1))}

    # ---- validation C: split-half re-linking -------------------------------
    # Cut each long payload's code in two halves, fingerprint each half on its
    # own, and ask: is the nearest second half (among 20k) from the same family?
    log("validation C")
    mh = MinHasher(64, seed=3)
    long_docs = [i for i in range(n) if len(skels[i].split(" ")) >= 80]
    pool = rng.sample(long_docs, min(20000, len(long_docs)))
    first, second = [], []
    for i in pool:
        toks = skels[i].split(" ")
        h = len(toks) // 2
        first.append(mh.sig(shingles(" ".join(toks[:h]))))
        second.append(mh.sig(shingles(" ".join(toks[h:]))))
    first, second = np.stack(first), np.stack(second)
    qn = min(2000, len(pool))
    self_hit = fam_hit = 0
    pool_fam = np.array([fam[i] for i in pool])
    for q in range(qn):
        sim = (second == first[q]).sum(axis=1)
        best = int(sim.argmax())
        self_hit += best == q
        fam_hit += pool_fam[best] == pool_fam[q]
    prior = sum((c / len(pool)) ** 2 for c in Counter(pool_fam.tolist()).values())
    val["split_half"] = {"queries": qn, "pool": len(pool), "nearest_is_same_payload": wilson(self_hit, qn),
                         "nearest_is_same_family": wilson(fam_hit, qn), "random_baseline_same_family": prior}

    # ---- write -----------------------------------------------------------
    summary = {
        "rows": len(rows), "docs": n, "kinds": dict(Counter(d["kind"] for d in docs)),
        "unique_skeletons": len(uniq), "families": len(size),
        "families_10plus": sum(1 for c in size.values() if c >= 10),
        "artifacts": len(art_docs), "artifact_types": dict(Counter(artifact_type(a) for a in art_docs)),
        "cross_family_artifacts": len(cross), "cross_family_by_type": dict(by_type),
        "secret_artifacts": sum(1 for a in art_docs if artifact_type(a) in SECRET_TYPES),
        "secret_cross_family": len(secret_cross),
        "secret_graph_edges": len(edges), "secret_graph_components": len(comps),
        "secret_graph_max_families_per_secret": MAX_FAM,
        "secret_spread_buckets": spread_buckets,
    }
    res = {"summary": summary, "validation": val, "families": fam_rows[:400],
           "cross_family_artifacts": cross[:500], "secret_clusters": secret_clusters,
           "secret_graph_edges": graph_edges, "self_chosen_names": name_rows[:200],
           "multi_name_families": multi_name[:60]}
    summary["self_chosen_names"] = len(name_rows)
    summary["multi_name_families"] = len(multi_name)
    with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1, default=str)
    log("done")
    print(json.dumps({"summary": summary, "validation": val}, indent=1, default=str))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
