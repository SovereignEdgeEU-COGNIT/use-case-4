"""Serverless-style single-file module for log line classification via embedding similarity.
Only external dependencies expected: transformers, accelerate.

Usage:
    from log_embedding_function import classify_log_line
    label = classify_log_line("Feb 20 10:15:32 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2")

If the local embedding database file (default: .emb) does not exist, it is built
from the sample logs (normal vs anomalous) embedded with a tiny model.
"""
from __future__ import annotations

import json
import os
import math
from typing import List, Dict, Tuple

from transformers import pipeline

# Small, fast embedding-capable model (feature extraction)
_MODEL_NAME = "sentence-transformers/paraphrase-MiniLM-L3-v2"
_DB_PATH_DEFAULT = ".emb"

_model_pipeline = None  # lazy-loaded global


def _get_model():
    global _model_pipeline
    if _model_pipeline is None:
        _model_pipeline = pipeline(
            task="feature-extraction",
            model=_MODEL_NAME,
            device=-1  # CPU
        )
    return _model_pipeline


def _mean_pool(token_vectors: List[List[float]]) -> List[float]:
    # token_vectors: seq_len x hidden
    if not token_vectors:
        return []
    seq_len = len(token_vectors)
    dim = len(token_vectors[0])
    sums = [0.0] * dim
    for tv in token_vectors:
        # Safety: ensure same length
        if len(tv) != dim:
            continue
        for i, v in enumerate(tv):
            sums[i] += float(v)
    return [s / seq_len for s in sums]


def _embed(text: str) -> List[float]:
    extractor = _get_model()
    # pipeline returns list: [ [ [hidden_dim] * seq_len ] ]
    output = extractor(text, truncation=True)
    # Expected shape: [1, seq_len, hidden]
    if isinstance(output, list) and output and isinstance(output[0], list):
        token_vectors = output[0]
    else:
        token_vectors = output
    embedding = _mean_pool(token_vectors)
    # Normalize vector (L2)
    norm = math.sqrt(sum(v * v for v in embedding)) or 1.0
    return [v / norm for v in embedding]


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb) or 1.0
    return dot / denom


def _sample_logs() -> List[Tuple[str, str]]:
    # Hard-coded from abnormal-and-normal-logs.md
    normals = [
        "Feb 20 10:15:32 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2",
        "Feb 20 10:30:12 server sshd[12345]: Received disconnect from 192.168.1.10 port 54321:11: Disconnected by user",
        "Feb 20 11:00:45 server sudo: user1 : TTY=pts/1 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/ls",
    ]
    anomalous = [
        "Feb 20 12:05:22 server sshd[22345]: Failed password for invalid user admin from 203.0.113.45 port 44444 ssh2",
        "Feb 20 12:05:23 server sshd[22346]: Failed password for root from 203.0.113.45 port 44445 ssh2",
        "Feb 20 12:10:30 server sshd[22350]: User nobody not allowed because account is locked",
        "Feb 20 12:20:15 server sudo: unknownuser : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "Feb 20 12:45:33 server su: pam_unix(su:session): session opened for user root by hacker(uid=1001)",
        "Feb 20 03:15:10 server sshd[30321]: Accepted password for user1 from 45.67.89.100 port 60000 ssh2",
        "Feb 20 13:00:00 server sudo: user2 : user NOT in sudoers ; TTY=pts/4 ; PWD=/home/user2 ; USER=root ; COMMAND=/bin/cat /etc/shadow",
    ]
    data = [(t, "normal") for t in normals] + [(t, "anomalous") for t in anomalous]
    return data


def construct_database(db_path: str = _DB_PATH_DEFAULT) -> None:
    dataset = _sample_logs()
    records = []
    for text, label in dataset:
        emb = _embed(text)
        # Optionally reduce precision to shrink file size
        emb_small = [round(v, 6) for v in emb]
        records.append({"text": text, "label": label, "embedding": emb_small})
    with open(db_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _load_database(db_path: str = _DB_PATH_DEFAULT) -> List[Dict]:
    items = []
    if not os.path.exists(db_path):
        return items
    with open(db_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "embedding" in obj and isinstance(obj["embedding"], list):
                    items.append(obj)
            except json.JSONDecodeError:
                continue
    return items


def get_nearby_label(text: str, db_path: str = _DB_PATH_DEFAULT) -> Tuple[str, float, Dict]:
    if not os.path.exists(db_path):
        construct_database(db_path)
    db = _load_database(db_path)
    if not db:
        return "unknown", -1.0, {}
    query_emb = _embed(text)
    best_label = "unknown"
    best_sim = -2.0
    best_item: Dict = {}
    for item in db:
        sim = _cosine(query_emb, item.get("embedding", []))
        if sim > best_sim:
            best_sim = sim
            best_label = item.get("label", "unknown")
            best_item = item
    return best_label, best_sim, best_item


def classify_log_line(log_line: str, db_path: str = _DB_PATH_DEFAULT) -> str:
    """Public serverless-style entrypoint. Returns closest label (normal|anomalous|unknown)."""
    log_line = (log_line or "").strip()
    if not log_line:
        return "unknown"
    label, _sim, _meta = get_nearby_label(log_line, db_path=db_path)
    return label


__all__ = [
    "classify_log_line",
    "get_nearby_label",
    "construct_database",
]

if __name__ == "__main__":  # Optional simple manual test
    sample = "Mar 29 12:06:24 server sshd[22346]: Failed password for root from 255.255.255.255 port 12345 ssh2"

    print(classify_log_line(sample))

    sample_2 = "Apr 9 16:15:32 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2"

    print(classify_log_line(sample_2))
