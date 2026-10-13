# Scan task list API

The legacy GET /api/v0/scans endpoint remains array-shaped for existing
clients. It returns the caller's scan tasks, or all tasks for admins — the
full set, without a truncation limit, so a retained task can never become
invisible behind a silent page cut.

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
          "expires_at": "2026-10-13T00:05:00Z",
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

Both endpoints require the submitter role or above. Submitters and reviewers
can only see their own tasks on both endpoints; only admins may see all tasks.
The filter applies before pagination and counting, so totals and `has_more`
do not expose other users' records. `owner_user_id` identifies task ownership; the
projection contains no source report or private acquisition data.

The task status and metadata endpoints also allow only the owner or an admin.
Reusing an initial scan during submission follows the same ownership check.
Reviewers retain access to submitted version reports through the review API;
that permission does not grant access to other users' raw scan tasks.

Admin callers with very large scan backlogs should prefer the paginated
v1 endpoint: the legacy array response carries the full set in one body.

## Lifecycle policy

The task response also exposes `lifecycle`, `auto_refresh`,
`delete_allowed`, and (while active) `execution_deadline_at` so clients do
not have to infer policy from internal states:

| Lifecycle | Duplicate scan | Delete | Auto refresh | Retention |
| --- | --- | --- | --- | --- |
| `scanning` | No | No | Continue until terminal/deadline | Until completion or total timeout |
| `llm_timeout` | No | Only if unbound | Continue until the callback settles | Unsubmitted: 30 days after failure; submitted: no automatic cleanup |
| `total_timeout` | No | Only if unbound | Continue until the callback settles | Unsubmitted: 30 days after failure; submitted: no automatic cleanup |
| `error` | No | Only if unbound | Continue until the callback settles | Unsubmitted: 30 days after failure; submitted: no automatic cleanup |
| `complete_unsubmitted` | No; delete first | Yes | Stop | 30 days after completion |
| `callback_pending` | No | No | Continue | No automatic cleanup |
| `submitted_reviewing` | No | No (use version policy) | Stop | No automatic cleanup |

Unsubmitted terminal scans expire at `finished_at + 30 days`. The UI uses
the server's `expires_at` to display the cleanup date and a remaining-time
countdown, with a prompt to submit successful scans soon. Failed scans instead
suggest starting a new scan. Expired records awaiting maintenance never show
a negative countdown.

Once attached to a version, tasks have no automatic cleanup deadline, including
failed tasks and versions that are approved, published, or rejected. No cleanup
reminder is shown for submitted tasks. Deleting a version through the management
API deletes its associated scan tasks in the same transaction, instead of
detaching them with another 30-day retention window. The version's independent
deletion audit entry is retained. Legacy orphan rows from older releases or
manual database changes still receive a deadline during maintenance.

For an attached task, `submission` contains `version_id`, `package_name`,
`version`, and `status` (the current version status). `submitted_reviewing` is
the backward-compatible lifecycle name for tasks that have entered the review
workflow; it does not mean that an approved/published version is still under
review. Display `submission.status` when available.

`llm_timeout` is listed only for compatibility with historical persisted
tasks. Current LLM deadline or scan-budget exhaustion completes the task with
a partial report instead of writing this task-level status.

`callback_pending` means the scan finished and is attached to a version,
but the producer completion callback has not been persisted yet. Clients
must keep polling; only `submitted_reviewing` confirms the submission
actually reached the review workflow.

All version-attached tasks are non-deletable through the scan endpoint, even
after their callback settles. Pending callbacks keep `auto_refresh` enabled.

A task under an active lease (a scan retry is currently claimed by a
worker) also cannot be deleted, even when its lifecycle row marks it as
deletable: such a delete is rejected with `409` until the lease expires.

Explicit deletion is available as `DELETE /api/v0/scan/{scan_id}`. It only
accepts unbound terminal tasks (scope S). Version-attached tasks return `409`;
they can only be removed through an eligible scope V operation. Only the task owner (or an admin) may delete a task;
reviewers, like submitters, receive `403` when accessing or deleting someone
else's task. Every explicit deletion writes a `scan_delete` audit record
containing the scan id, the owner, and the operator.

## Version deletion matrix

| Version status | Owner (submitter/reviewer) | Admin | Scope / label |
| --- | --- | --- | --- |
| `draft`, `pending_review`, `changes_requested`, `rejected`, `error` | Yes, own version only | Yes | V / 撤回并删除提交 |
| `yanked` | No | Yes | V / 删除版本 |
| `submitted`, `scanning`, `resubmitted`, `approved`, `published` | No | No | N / no button |

Unknown states fail closed. Reviewer privileges do not allow deleting another
submitter's version. `GET /api/v0/producer/versions/{id}/deletion-preview` returns
the authorized deletion scope, current status, and counts of associated scans,
reports and review records. The UI opens a checklist and requires acknowledgement
followed by a second confirmation dialog. Only then does it send
`DELETE /api/v0/producer/versions/{id}` with
`{"confirmed": true, "expected_status": "<preview status>"}`.

Deletion rechecks ownership and the relational status under a row lock. Status
changes, running associated scans, active leases and undelivered callbacks block
the operation (`409`). Version deletion, attached scan removal and deletion audit
creation are atomic. Version-scoped reports, review/installation records and
trust scores cascade with the version. The package container, other versions and
independent audit history remain; no other version is automatically published.
Deleting the version referenced by `latest_version` clears that pointer and
returns the package to draft rather than leaving a dangling published entry.

Scope S uses the single-confirmation label **删除扫描记录**. Active tasks,
version-bound tasks and live leases are scope N, including for administrators.

## Submission navigation and existing packages

`/scans` defaults to **My submitted versions** for submitters, reviewers, and
admins alike. It queries `/api/v0/producer/versions?submitter_id=<current-user>`
independently of scan records. A separate tab lists the user's scans, or global
scans for admins only. Removing a scan record therefore does not remove
the surviving version from the personal submissions view. Delete controls and
confirmation/success messages explicitly distinguish scan records from package
versions and review history; deleting a scan does not release the package name.

`GET /api/v0/producer/packages/lookup?name=<exact-name>` is an authenticated,
read-only lookup that includes unpublished packages. Owners, reviewers, and
admins receive the package id/name/status and version id/number/status/submission
time only. Another submitter receives `403`; an available name returns `null`.
The literal lookup route is registered before the package-id route.

The generic submit page checks the scanned/edited package name and rechecks
immediately before creating a package. Existing non-draft submissions are routed
to their status page or to new-version creation. Resubmission is offered only
for `changes_requested`, `error`, and `resubmitted` versions; rejected versions
require a new version. A completed unsubmitted scan can be carried to either
flow using `scan=<scan_id>`, with existing server-side ownership/source checks
still applied. Draft resumption remains subject to the existing source-match
validation. No lookup/navigation operation deletes packages or review history.
