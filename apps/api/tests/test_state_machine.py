"""状态机单元测试 — 15 合法跳转 + 8 非法跳转 = 23 条。"""

from __future__ import annotations

import pytest

from src.services.producer import ProducerServiceError, validate_transition


# ── 合法跳转 (15 条) ──────────────────────────────────────

_VALID_TRANSITIONS = [
    # 提交链路
    ("draft", "submitted", "首次提交"),
    ("submitted", "scanning", "进入扫描队列"),
    ("scanning", "pending_review", "扫描完成待审核"),
    ("scanning", "error", "扫描失败"),
    ("error", "submitted", "重新触发扫描"),
    # 审核链路
    ("pending_review", "approved", "审核通过"),
    ("pending_review", "rejected", "审核驳回"),
    ("pending_review", "changes_requested", "要求修改"),
    # 发布链路
    ("approved", "published", "管理员发布上线"),
    ("approved", "rejected", "通过后回退驳回"),
    ("published", "yanked", "管理员下架"),
    ("yanked", "published", "恢复上架"),
    # 重新提交流程
    ("rejected", "resubmitted", "驳回后修改重提"),
    ("resubmitted", "scanning", "重提交后进入扫描"),
    ("changes_requested", "scanning", "修改后重新扫描"),
]


@pytest.mark.parametrize(("current", "target", "desc"), _VALID_TRANSITIONS)
def test_valid_transition(current: str, target: str, desc: str) -> None:
    """合法跳转不应抛出异常。"""
    try:
        validate_transition(current, target)
    except ProducerServiceError as exc:
        pytest.fail(f"合法跳转 '{current}' → '{target}' ({desc}) 意外失败: {exc}")


# ── 非法跳转 (8 条) ──────────────────────────────────────

_INVALID_TRANSITIONS = [
    # 跳过审核
    ("draft", "published", "跳过扫描+审核+审批"),
    ("draft", "approved", "跳过扫描+审核"),
    ("scanning", "published", "未审完就上线"),
    ("pending_review", "published", "跳过 approved 审批环节"),
    ("rejected", "published", "驳回后直接上线"),
    ("rejected", "approved", "驳回后不能直接通过"),
    ("changes_requested", "approved", "修改完必须重新扫描"),
    # 异常回退
    ("yanked", "approved", "下架后应回 published"),
]


@pytest.mark.parametrize(("current", "target", "desc"), _INVALID_TRANSITIONS)
def test_invalid_transition(current: str, target: str, desc: str) -> None:
    """非法跳转必须抛出 ProducerServiceError。"""
    with pytest.raises(ProducerServiceError, match="状态跳转非法"):
        validate_transition(current, target)
