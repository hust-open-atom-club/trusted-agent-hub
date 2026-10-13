"""Deletion policy shared by preview and transactional version deletion."""

WITHDRAWABLE_STATUSES = frozenset({
    "draft", "pending_review", "changes_requested", "rejected", "error",
})


class VersionDeletionError(Exception):
    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


def deletion_action(status: str, *, is_admin: bool) -> str | None:
    if status in WITHDRAWABLE_STATUSES:
        return "撤回并删除提交"
    if status == "yanked" and is_admin:
        return "删除版本"
    return None
