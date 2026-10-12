"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách biệt trách nhiệm giữa Run A (untrusted content) và Run B (private data).
Kiểm tra Policy Enforcement Point (PEP) tại mọi biên giới gọi tool.
Ghi nhận đầy đủ audit trail vào tamper-evident ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agent import pii, policy, tools
from agent.policy import PolicyContext
from agent import ledger

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CUSTOMERS_PATH = DATA_DIR / "customers.json"


class RunnerScaffoldPending(NotImplementedError):
    """Scaffold pending exception for backward compatibility with test_scaffold_dispatch."""


def _compute_args_hash(data: dict) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu thông qua kiến trúc Trifecta Split có PEP và Ledger."""
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    agent_id = "lab24-agent"

    # =========================================================================
    # RUN A: untrusted content boundary
    # Quyền: search_docs (internal). KHÔNG read_customer, KHÔNG http_post.
    # =========================================================================
    sd_context = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer", "http_post"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed_sd, reason_sd = policy.check(sd_context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": f"{run_id}-a",
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "search_docs",
        "args_hash": _compute_args_hash({"query": message}),
        "classification": "internal",
        "decision": "allow" if allowed_sd else "deny",
        "reason": reason_sd,
    }, ledger_path)

    if not allowed_sd:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Quét injection để phát hiện chỉ thị tấn công (nhưng KHÔNG dùng customer_id tự do của attacker)
    combined_raw_text = "\n\n".join(d.get("text", "") for d in docs)
    injected = llm.find_injection(combined_raw_text)

    # Sanitize văn bản tài liệu bằng PII gate trước khi dùng tiếp
    for d in docs:
        if "text" in d:
            d["text"] = pii.redact(d["text"])

    # Trifecta split: Run A CHỈ truyền typed data (danh sách số ticket_id từ tên file) sang Run B
    ticket_ids: list[int] = []
    for d in docs:
        doc_id = d.get("id", "")
        match = re.search(r"ticket-(\d+)", doc_id)
        if match:
            ticket_ids.append(int(match.group(1)))

    # =========================================================================
    # RUN B: private data boundary
    # Quyền: read_customer (restricted). KHÔNG nhận raw free text từ Run A.
    # Suy customer_id từ NGUỒN TIN CẬY (data/customers.json: related_tickets).
    # =========================================================================
    customers_data: list[dict] = []
    if CUSTOMERS_PATH.exists():
        customers_data = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))

    ticket_ids_set = set(ticket_ids)
    target_customer_ids: list[str] = []
    for cust in customers_data:
        related = cust.get("related_tickets", [])
        if any(t in ticket_ids_set for t in related):
            c_id = cust.get("customer_id")
            if c_id and c_id not in target_customer_ids:
                target_customer_ids.append(c_id)

    collected_records: list[dict] = []
    for cust_id in target_customer_ids:
        rc_context = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer", "http_post"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed_rc, reason_rc = policy.check(rc_context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"{run_id}-b",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "read_customer",
            "args_hash": _compute_args_hash({"customer_id": cust_id}),
            "classification": "restricted",
            "decision": "allow" if allowed_rc else "deny",
            "reason": reason_rc,
        }, ledger_path)

        if allowed_rc:
            try:
                record = tools.read_customer(cust_id)
                collected_records.append(record)
            except tools.ToolError:
                pass

    # =========================================================================
    # EGRESS POLICY: kiểm soát http_post nếu phát hiện chỉ thị exfiltration
    # =========================================================================
    if injected is not None:
        target_url = getattr(injected, "target_url", "http://127.0.0.1:10024/reconcile")
        post_context = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer", "http_post"),
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allowed_post, reason_post = policy.check(post_context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"{run_id}-egress",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "http_post",
            "args_hash": _compute_args_hash({"url": target_url}),
            "classification": "restricted",
            "decision": "allow" if allowed_post else "deny",
            "reason": reason_post,
        }, ledger_path)

        if allowed_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)
