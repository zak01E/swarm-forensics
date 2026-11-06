"""Coding-style fingerprints and near-duplicate families.

The fingerprint deliberately ignores *which* secret, service or repo a payload
touches: every pseudonym label is replaced by its type. Two payloads end up in
the same family because they are written the same way, not because they use the
same credential. That keeps the artifact signal free for validation.
"""
import re
import zlib

import numpy as np

from .load import LABEL, REDACTED

TOKEN = re.compile(r"§\w+|[A-Za-z_$][A-Za-z0-9_$]*|\d+|\S")
MAX_TOKENS = 400
SHINGLE = 5
P = (1 << 31) - 1


def skeleton(text):
    t = LABEL.sub(lambda m: "§" + "".join(w[0] for w in m.group(1).split()), text)
    t = REDACTED.sub(lambda m: "§r" + m.group(1)[:6], t)
    t = t.replace("[REDACTED SENSITIVE CONTENT]", "§sens")
    t = re.sub(r"\[[A-Z][A-Z ]+\]", "§lab", t)
    t = re.sub(r"\d+", "0", t)
    return " ".join(TOKEN.findall(t)[:MAX_TOKENS])


def doc_skeleton(doc):
    parts = [doc["text"]] + doc["child_texts"]
    return skeleton("\n".join(parts))


def shingles(skel, k=SHINGLE):
    toks = skel.split(" ")
    if len(toks) <= k:
        return {zlib.crc32(skel.encode())}
    return {zlib.crc32(" ".join(toks[i:i + k]).encode()) for i in range(len(toks) - k + 1)}


class MinHasher:
    def __init__(self, n_perm=64, seed=0):
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, P, n_perm, dtype=np.int64)
        self.b = rng.integers(0, P, n_perm, dtype=np.int64)

    def sig(self, sh):
        x = np.fromiter(sh, dtype=np.int64) % P
        return ((self.a[:, None] * x[None, :] + self.b[:, None]) % P).min(axis=1)


class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, i):
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, i, j):
        i, j = self.find(i), self.find(j)
        if i != j:
            self.p[max(i, j)] = min(i, j)


def families(skels, n_perm=64, bands=16, threshold=0.6, seed=0):
    """Cluster unique skeletons. Returns (family id per skeleton, signatures).

    LSH on MinHash signatures proposes candidates; a candidate joins a bucket's
    first member only if their estimated Jaccard similarity is >= threshold.
    This star check keeps the cost linear in bucket size.
    """
    mh = MinHasher(n_perm, seed)
    sigs = np.stack([mh.sig(shingles(s)) for s in skels])
    rows = n_perm // bands
    uf = UnionFind(len(skels))
    for b in range(bands):
        block = sigs[:, b * rows:(b + 1) * rows]
        buckets = {}
        for i, key in enumerate(map(bytes, block)):
            buckets.setdefault(key, []).append(i)
        for members in buckets.values():
            if len(members) < 2:
                continue
            head = members[0]
            sim = (sigs[members[1:]] == sigs[head]).mean(axis=1)
            for m, s in zip(members[1:], sim):
                if s >= threshold:
                    uf.union(head, m)
    roots = [uf.find(i) for i in range(len(skels))]
    return roots, sigs


# Human-readable traits, used to describe a family (not to build it).
TRAITS = {
    "fetch()": r"\bfetch\(",
    "XMLHttpRequest": r"XMLHttpRequest",
    "python exec+urlopen": r"exec\(.*urlopen",
    "script-tag loader": r"<script src=",
    "image beacon": r"new Image",
    "gzip DecompressionStream": r"DecompressionStream",
    "prints to page (innerText)": r"document\.body\.innerText",
    "document.write": r"document\.write",
    "string accumulator (x+=)": r"\b[a-z]\+='",
    "lower-case headers": r"'x-api-key'|'content-type'",
    "Title-Case headers": r"'X-API-Key'|'Content-Type'",
    "Bearer token": r"Bearer ",
    "Hugging Face API": r"huggingface\.co",
    "reads location.hash": r"location\.hash",
    "agent_id field": r"agent_id",
}
TRAIT_RX = {k: re.compile(v) for k, v in TRAITS.items()}


def traits(text):
    return [k for k, rx in TRAIT_RX.items() if rx.search(text)]
