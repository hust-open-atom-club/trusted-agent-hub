# Scan task list API

The legacy GET /api/v0/scans endpoint remains array-shaped for existing
clients. It returns the caller's scan tasks, or all tasks for admins.

The management UI uses the versioned paginated endpoint:

    GET /api/v1/scans?limit=50&offset=0
    Authorization: Bearer <access-token>

The response is:

    {
      "items": [
        {
          "scan_id": "scan-123",
          "status": "complete",
          "package_name": "example",
          "created_at": "2026-09-13T00:00:00Z",
          "updated_at": "2026-09-13T00:05:00Z",
          "finished_at": "2026-09-13T00:05:00Z",
          "expires_at": "2026-10-13T00:00:00Z",
          "client_request_id": "request-123",
          "execution_deadline_at": null,
          "lifecycle": "complete_unsubmitted",
          "auto_refresh": false,
          "delete_allowed": true,
          "owner_user_id": "user-123"
        }
      ],
      "total": 1,
      "limit": 50,
      "offset": 0,
      "has_more": false
    }

Both endpoints require the submitter role or above. The legacy endpoint keeps
its original owner-scoped behavior for submitters and reviewers; admins may
see all tasks. On the v1 management endpoint, reviewers and admins may see all
tasks. `owner_user_id` identifies task ownership for that management view; the
projection contains no source report or private acquisition data.

## Lifecycle policy

The task response also exposes `lifecycle`, `auto_refresh`,
`delete_allowed`, and (while active) `execution_deadline_at` so clients do
not have to infer policy from internal states:

| Lifecycle | Duplicate scan | Delete | Auto refresh | Retention |
| --- | --- | --- | --- | --- |
| `scanning` | No | No | Continue until terminal/deadline | Until completion or total timeout |
| `llm_timeout` | No; delete first | No while a callback is pending | Continue until the callback settles | 30 days after failure |
| `total_timeout` | No; delete first | No while a callback is pending | Continue until the callback settles | 30 days after failure |
| `error` | No; delete first | No while a callback is pending | Continue until the callback settles | 30 days after failure |
| `complete_unsubmitted` | No; delete first | Yes | Stop | 30 days after completion |
| `callback_pending` | No | No | Continue | Until the callback is delivered |
| `submitted_reviewing` | No | Yes | Stop | No automatic cleanup |

`callback_pending` means the scan finished and is attached to a version,
but the producer completion callback has not been persisted yet. Clients
must keep polling; only `submitted_reviewing` confirms the submission
actually reached the review workflow.

A terminal failure (`error`, `llm_timeout`, `total_timeout`) that is still
attached to a version whose submission callback has not been delivered is
also not deletable yet. Such rows keep `auto_refresh` set until the
callback settles, so a client that trusts only this projection does not
freeze the list behind a disabled delete button.

A task under an active lease (a scan retry is currently claimed by a
worker) also cannot be deleted, even when its lifecycle row marks it as
deletable: such a delete is rejected with `409` until the lease expires.

Explicit deletion is available as `DELETE /api/v0/scan/{scan_id}`. It only
accepts terminal tasks and leaves an attached version and its version-scoped
scan report intact. Only the task owner (or an admin) may delete a task;
reviewers can list every task through v1 but receive `403` when deleting
someone else's. Every explicit deletion writes a `scan_delete` audit record
containing the scan id, the owner, and the operator.
