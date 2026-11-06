"""Load the Swarm Traces redacted dump and build one 'document' per payload.

A document is a payload plus the texts recovered from it (children linked by
parent_id). Rows without a parent that are not payloads become their own
document, so nothing is dropped.
"""
import gzip
import json
import re
from collections import defaultdict

# Stable pseudonym labels written by the redaction pipeline, e.g.
# [CREDENTIAL 170], [SERVICE 2 URL 3], [PROXY 4 URL 1], [HF REPO 12]
LABEL = re.compile(r"\[([A-Z][A-Z]+(?: [A-Z]+)*)((?: \d+)(?: [A-Z]+ \d+)*)\]")
# Numbered redactions, e.g. [REDACTED:destination:002404]
REDACTED = re.compile(r"\[REDACTED:([a-z_]+):(\d+)\]")

# Artifact types that point at a shared, re-usable thing (a secret, a service,
# a repo, an endpoint). Content-hash style labels (ENCODED BLOB, opaque_*) are
# almost always unique per row and say nothing about sharing, so they are left out.
SHARED_TYPES = {
    "CREDENTIAL", "SERVICE URL", "SERVICE HOST", "PROXY URL", "SHORTENER URL",
    "HF REPO", "USER", "IP ADDRESS", "WORKLOAD ID", "INTERNAL HOST",
    "WEBHOOK URL", "EMAIL", "REDIRECT URL", "ENV VALUE", "INFRA CONFIG",
    "CLOUD RESOURCE", "DOCKER REPO",
    "R:destination", "R:source_identifier", "R:source_path", "R:runtime_identifier",
    "R:secret_key", "R:bearer_token", "R:username", "R:whoami_name", "R:hf_repo",
    "R:jwt_claim_identifier", "R:repo_locator", "R:partial_repo_name",
    "R:network_address", "R:aws_auth_value", "R:service_path",
}


def label_type(full_label_body):
    """'SERVICE 2 URL 3' -> 'SERVICE URL'; 'CREDENTIAL 170' -> 'CREDENTIAL'."""
    return " ".join(w for w in full_label_body.split() if not w.isdigit())


def artifacts(text):
    out = set()
    for m in LABEL.finditer(text):
        body = m.group(1) + m.group(2)
        t = label_type(body)
        if t in SHARED_TYPES:
            out.add(f"[{body}]")
    for m in REDACTED.finditer(text):
        t = "R:" + m.group(1)
        if t in SHARED_TYPES:
            out.add(f"[{m.group(1)}:{m.group(2)}]")
    return out


def artifact_type(a):
    a = a.strip("[]")
    if ":" in a:
        return "R:" + a.split(":")[0]
    return label_type(a)


def load(path):
    rows = [json.loads(line) for line in gzip.open(path, "rt", encoding="utf-8")]
    byid = {r["id"]: r for r in rows}
    children = defaultdict(list)
    for r in rows:
        p = r.get("parent_id")
        if p and p in byid:
            children[p].append(r)
    docs = []
    for r in rows:
        p = r.get("parent_id")
        if p and p in byid:
            continue  # folded into its parent
        kids = children.get(r["id"], [])
        docs.append({
            "id": r["id"],
            "kind": r["kind"],
            "text": r["text"],
            "child_texts": [k["text"] for k in kids],
            "child_kinds": [k["kind"] for k in kids],
        })
    return rows, docs
