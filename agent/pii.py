"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex recognizer cho CCCD, SĐT, STK, Email tiếng Việt.
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BANK_ACCOUNT_RE = re.compile(r"(?i)(?:STK|số tài khoản)\s+(\d{8,19})\b")
_CCCD_RE = re.compile(r"\b\d{12}\b")
_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản.

    Trả về danh sách {"type": str, "start": int, "end": int} được sắp xếp theo start.
    """
    entities: list[dict] = []
    occupied: set[int] = set()

    # 1. EMAIL
    for m in _EMAIL_RE.finditer(text):
        start, end = m.start(), m.end()
        entities.append({"type": "EMAIL", "start": start, "end": end})
        for i in range(start, end):
            occupied.add(i)

    # 2. VN_BANK_ACCOUNT (đi kèm tiền tố STK / số tài khoản)
    for m in _BANK_ACCOUNT_RE.finditer(text):
        start = m.start(1)
        end = m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
        for i in range(start, end):
            occupied.add(i)

    # 3. VN_CCCD (12 chữ số liên tiếp)
    for m in _CCCD_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            for i in range(start, end):
                occupied.add(i)

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            for i in range(start, end):
                occupied.add(i)

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay thế từ cuối về đầu để không làm lệch offset ký tự
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    result = text
    for ent in sorted_entities:
        result = result[: ent["start"]] + f"[REDACTED_{ent['type']}]" + result[ent["end"] :]
    return result
