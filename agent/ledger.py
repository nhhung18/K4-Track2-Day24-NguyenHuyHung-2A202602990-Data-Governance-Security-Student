"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng với hash chain.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry_without_hash: dict) -> str:
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một entry vào ledger với tamper-evident hash chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", "0" * 64)
            except Exception:
                prev_hash = "0" * 64

    entry_copy = dict(entry)
    entry_copy["prev_hash"] = prev_hash
    entry_copy["hash"] = _compute_hash(entry_copy)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry_copy, ensure_ascii=False) + "\n")

    return entry_copy


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của chuỗi hash trong ledger."""
    path = Path(path)
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True

    lines = [line.strip() for line in content.splitlines() if line.strip()]
    expected_prev = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Reason không bao giờ được để trống
        if not entry.get("reason"):
            return False

        # 2. prev_hash phải khớp hash của dòng trước
        if entry.get("prev_hash") != expected_prev:
            return False

        # 3. hash của dòng phải khớp khi tính lại
        saved_hash = entry.get("hash")
        if not saved_hash:
            return False

        without_hash = {k: v for k, v in entry.items() if k != "hash"}
        recalculated = _compute_hash(without_hash)
        if recalculated != saved_hash:
            return False

        expected_prev = saved_hash

    return True
