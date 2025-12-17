"""Serverless-style single-file module for log line classification via embedding similarity.
Only external dependencies expected: transformers, accelerate.

Usage:
    from log_embedding_function import classify_log_line
    label = classify_log_line("Feb 20 10:15:32 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2")

If the local embedding database file (default: .emb) does not exist, it is built
from the sample logs (normal vs anomalous) embedded with a tiny model.
"""


def classify_log_line(log_line: str, db_path: str = ".emb", _state={"model_pipeline": None}) -> str:
    """Public serverless-style entrypoint. Returns closest label (normal|anomalous|unknown)."""

    import json
    import math
    import os
    import time
    from transformers import pipeline

    start_time = time.perf_counter()
    model_name = "sentence-transformers/paraphrase-MiniLM-L3-v2"

    def _get_model():
        if _state["model_pipeline"] is None:
            _state["model_pipeline"] = pipeline(
                task="feature-extraction",
                model=model_name,
                device=-1,
            )
        return _state["model_pipeline"]

    def _mean_pool(token_vectors):
        if not token_vectors:
            return []
        seq_len = len(token_vectors)
        dim = len(token_vectors[0])
        sums = [0.0] * dim
        for tv in token_vectors:
            if len(tv) != dim:
                continue
            for i, value in enumerate(tv):
                sums[i] += float(value)
        return [s / seq_len for s in sums]

    def _embed(text: str):
        extractor = _get_model()
        output = extractor(text, truncation=True)
        if isinstance(output, list) and output and isinstance(output[0], list):
            token_vectors = output[0]
        else:
            token_vectors = output
        embedding = _mean_pool(token_vectors)
        norm = math.sqrt(sum(v * v for v in embedding)) or 1.0
        return [v / norm for v in embedding]

    def _cosine(a, b):
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

    def _sample_logs():
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
        return [(text, "normal") for text in normals] + [(text, "anomalous") for text in anomalous]

    def _ensure_database(path: str):
        if os.path.exists(path):
            return
        records = []
        for text, label in _sample_logs():
            embedding = _embed(text)
            records.append(
                {
                    "text": text,
                    "label": label,
                    "embedding": [round(v, 6) for v in embedding],
                }
            )
        with open(path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _load_database(path: str):
        if not os.path.exists(path):
            return []
        items = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and isinstance(entry.get("embedding"), list):
                    items.append(entry)
        return items

    def _get_nearby_label(text: str, path: str):
        _ensure_database(path)
        database = _load_database(path)
        if not database:
            return "unknown", -1.0, {}
        query_embedding = _embed(text)
        best_label = "unknown"
        best_similarity = -2.0
        best_item = {}
        for item in database:
            similarity = _cosine(query_embedding, item.get("embedding", []))
            if similarity > best_similarity:
                best_label = item.get("label", "unknown")
                best_similarity = similarity
                best_item = item
        return best_label, best_similarity, best_item

    log_line = (log_line or "").strip()
    if not log_line:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return f"unknown - {duration_ms:.2f}"
    label, _, _ = _get_nearby_label(log_line, db_path)
    duration_ms = (time.perf_counter() - start_time) * 1000.0
    return f"{label} - {duration_ms:.2f}"


__all__ = [
    "classify_log_line",
]
