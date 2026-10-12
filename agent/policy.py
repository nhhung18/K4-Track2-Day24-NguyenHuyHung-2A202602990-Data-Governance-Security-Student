"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PRINCIPALS_PATH = _DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if not _PRINCIPALS_PATH.exists():
        return {}
    return json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách an toàn trước khi cho phép gọi tool.

    Mọi quyết định (allow/deny) đều phải có reason không rỗng.
    """
    # 1. Rule TỐI THIỂU: restricted + egress_enabled -> DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Deny: restricted data classification with egress enabled is prohibited"

    # 2. Kiểm tra thời hạn TTL (expires_at)
    if context.expires_at:
        try:
            exp_dt = datetime.fromisoformat(context.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > exp_dt:
                return False, f"Deny: session expired at {context.expires_at}"
        except Exception as exc:
            return False, f"Deny: invalid expires_at timestamp ({exc})"

    # 3. Kiểm tra principal
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"Deny: unknown principal '{context.principal_id}'"

        principal_info = principals[context.principal_id]

        # 4. Kiểm tra mục đích (request_purpose)
        allowed_purposes = principal_info.get("purposes", [])
        if context.request_purpose and context.request_purpose not in allowed_purposes:
            return False, (
                f"Deny: purpose '{context.request_purpose}' is not authorized "
                f"for principal '{context.principal_id}'"
            )

        # 5. Quyền hiệu lực: giao giữa principal.allowed_tools, agent_scopes, và parent_scopes
        effective_tools = set(principal_info.get("allowed_tools", []))
        if context.agent_scopes:
            effective_tools = effective_tools.intersection(context.agent_scopes)

        if context.delegation_depth > 0:
            if context.parent_scopes:
                effective_tools = effective_tools.intersection(context.parent_scopes)
            else:
                effective_tools = set()

        # 6. Kiểm tra requested_tool
        if context.requested_tool and context.requested_tool not in effective_tools:
            return False, (
                f"Deny: tool '{context.requested_tool}' is not permitted for principal "
                f"'{context.principal_id}' in current scope"
            )

    return True, (
        f"Allow: request permitted for principal '{context.principal_id or 'anonymous'}' "
        f"with tool '{context.requested_tool or 'none'}'"
    )
