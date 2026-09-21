# LLM security adjudication

The LLM reviewer is a bounded adjudication layer for findings whose real risk
depends on code or instruction context. It does not assign package grades and
it never deletes the scanner's original evidence.

## Severity contract

- `static_severity` is the immutable detector result.
- `effective_severity` is the score-facing result.
- `severity` mirrors `effective_severity` for compatibility.
- `llm_adjudication_eligible` records whether policy permits a semantic
  decision to change `effective_severity`.

Semantic text, context-dependent findings, and high/critical findings in
semantic security categories can be eligible. A finding with
`kind=vulnerability` and `disposition=confirmed_vulnerability` is protected
and cannot be downgraded by an LLM verdict.

Before review completes, an eligible finding retains its effective severity
and requires manual review. This also applies when no provider is configured,
the provider call fails, or the source context is missing or incomplete.
Those provider, configuration, and context failures do not make an otherwise
complete static scan report partial. Only exhaustion of the LLM review deadline
or the remaining scan budget changes the report status to `partial`.

## Review input and prompt contract

Each candidate contains the scanner's structured source/sink semantics and a
redacted source excerpt for the primary location and up to three additional
detector/occurrence locations. The default limits are 60 lines per location,
8 KiB per finding, and 64 KiB per provider request batch. Resetting the batch
budget prevents findings late in a large report from losing all source context
only because earlier candidates consumed a run-wide allowance.

The prompt instructs each judge to trace the source, sink, activation path,
trust boundary, safeguards, and preconditions using only the supplied text.
The response must state whether evidence is sufficient and cite one complete
source line, limited to 160 characters, from a supplied file/line. The server
matches the complete line against the delivered source and records a
server-generated SHA-256 for it; a partial or unmatched line is insufficient
evidence. Package text is treated as untrusted data and is never executed or
followed as an instruction.

Reports expose enough metadata to reproduce and audit the review boundary:

- `prompt_audit` contains prompt/schema versions, system/template SHA-256
  hashes, and a SHA-256 for every rendered request payload.
- `review_configuration` records provider, model, batch size, concurrency,
  temperature, and output-token limit; credentials and custom base URLs are
  never reported.
- `context_coverage` summarizes complete, partial, and missing contexts.
- each decision carries `context_audit`, `supporting_evidence`, and
  `missing_context`.

## Decision gates

Two independent judges are required. A third judge arbitrates disagreement,
but only when the two judges disagree on a decisive verdict. When neither
judge reaches one, a single extra verdict could never form the two agreeing
verdicts a decision requires, so the finding is recorded as unresolved for
manual review without spending a third request. Normal high/critical findings
may be reviewed for explanation, but only eligible findings may be downgraded.

| Result | Effective-severity action |
| --- | --- |
| Harmful/risky consensus | Preserve or increase severity; never reduce it |
| Benign consensus with all gates satisfied | Set effective severity to `info`; preserve static severity |
| Missing/partial context, invalid citation, low confidence, disagreement, or failed call | Preserve pre-review severity and require manual review |
| Benign verdict for a confirmed vulnerability | Block the downgrade and require manual review |

A benign downgrade requires all of the following:

1. two agreeing reviews;
2. confidence at or above `0.85`;
3. `evidence_sufficient=true`;
4. complete, non-truncated scanner context;
5. at least one file/line citation containing a complete delivered source line;
6. an eligible, non-protected finding.

The applied outcome is recorded in `llm_adjudication_action`, while
`llm_effective_severity_before` retains the score-facing value seen before the
decision.

## Review budget

The review stage runs inside a wall-clock budget so one large package cannot
occupy a worker indefinitely. The default is 900 seconds; set
`TAH_LLM_REVIEW_DEADLINE_SECONDS` to change it. The effective budget is the
smaller of that value and the scan's remaining time after reserving report
finalization time. The reserve defaults to 120 seconds and can be changed with
`TAH_SCAN_FINALIZATION_RESERVE_SECONDS`.

Candidates are reviewed in batches (`REVIEW_BATCH_SIZE`, 8 per batch) with two
judges per batch, so a package with `N` candidates costs at least
`2 * ceil(N / 8)` provider calls. Each scan logs that estimate with the budget
when the review starts. Judge calls and any later arbitration calls use bounded
parallelism. `TAH_LLM_REVIEW_MAX_CONCURRENCY` defaults to 2 and accepts values
from 1 through 8. If too little scan time remains, LLM review is skipped.
If the review reaches either deadline, completed verdicts are retained,
unresolved findings are marked for manual review, and the pipeline continues
through scoring and report persistence. The outer task finishes as `complete`,
while `scan_status.state` and the status API's `report_status` are `partial`.
`llm_review.reason_code`, `phase`, `attempt`, and the reviewed/pending counts
explain where and why review stopped. A total scan timeout before a valid report
is saved remains a terminal failure with `report_status=report_unavailable`.
The task-level `llm_timeout` status is retained only so historical persisted
tasks remain readable; current scans do not produce it.

## Operator verification

Run the focused adjudication and context tests from the repository root:

```powershell
New-Item -ItemType Directory -Force .pytest-tmp/llm-adjudication | Out-Null
python -m pytest apps/api/tests/test_llm_semantic_consensus.py apps/api/tests/test_llm_review_fail_closed.py apps/api/tests/test_source_privacy.py --basetemp .pytest-tmp/llm-adjudication -q
```

When reviewing a produced report, verify the template and payload hashes,
provider/model, context delivery status, cited lines, confidence, number of
rounds, and final `llm_adjudication_action` together. A label such as
`llm:likely-benign` alone is not evidence that a downgrade was applied.
