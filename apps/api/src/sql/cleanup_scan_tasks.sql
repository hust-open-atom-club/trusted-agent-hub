-- Cleanup of expired scan-task retention rows.
-- Keep this predicate aligned with ProducerRepository.delete_expired_scan_tasks().
--
-- A failed task that still owes a version a completion callback
-- (callback_status = 'pending') is NEVER deleted: the recovery worker
-- needs its row to redrive the submission callback.
DELETE FROM scan_tasks
WHERE expires_at IS NOT NULL
  AND expires_at <= CURRENT_TIMESTAMP
  AND (
    (
      status IN ('error', 'llm_timeout', 'total_timeout')
      AND (
        version_id IS NULL
        OR callback_status IN ('delivered', 'not_required')
      )
    )
    OR (status = 'complete' AND version_id IS NULL)
  );
