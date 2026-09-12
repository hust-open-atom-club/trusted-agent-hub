# Scanner benchmark corpus

This directory contains the authoritative `labels-v2.json` deterministic,
human-labeled quality benchmark for the risk scanner. It measures whether the
scanner identifies the right issue, at the right severity and package grade,
without teaching the benchmark that a known false positive or false negative is
correct. The v2 corpus currently contains 58 cases; the acceptance criterion is
the coverage map, not a fixed case count.

## Running the benchmark

From the repository root:

```console
python benchmarks/runner.py --config benchmarks/labels-v2.json
python benchmarks/runner.py --config benchmarks/labels-v2.json --check
```

The first command always reports observed differences. The second additionally
returns a non-zero exit status when:

- a `blocking` case differs from its target;
- any fixture content hash has drifted;
- any scan is incomplete; or
- any scanner rule raises an exception; or
- precision, recall, benign high/critical false-positive rate, malicious
  high/critical recall, or corpus size crosses a configured `quality_gates`
  threshold.

An `observe` difference is visible but does not fail the case-level comparison.
Every observe case must include a non-empty `known_gap.reason` and a
`planned_pr`; all cases, including observe cases, still contribute to the
aggregate quality gates.

The legacy format remains available and is still accepted:

```console
python benchmarks/runner.py --config benchmarks/expected-results.json --check
```

`expected-results.json` is explicitly marked `legacy-v1` and is retained only
for compatibility. It is not a complete rule-coverage source and must not be
used as the benchmark authority.

## Offline and deterministic execution

Corpus files are scanned as text; none of the commands or services in a sample
are executed. The runner installs an in-memory OSV fixture before every scan,
so dependencies never cause a real OSV or external network request. The static
scanner does not invoke the LLM reviewer, and the benchmark does not load a
model client.

Each case records the scanner's content-tree SHA-256. Fixture drift is fatal in
check mode regardless of enforcement. The scoring engine receives the same
fixed source, verification, author, review, and feedback inputs on every run.
The authoritative v2 labels use `fixture_source_tree_sha256`, a normalized
content-tree identity independent of branch history, merge strategy, and text
EOL policy. The runner verifies it before scanning and preserves symlink
targets without following them. Older schema-v2 configs may still use
`fixture_source_commit_hash` or the deprecated `scanner_source_commit_hash`
commit references; those remain compatibility-only and should not be used for
the authoritative labels. For ordinary fixture cases, the runner derives a
deterministic acquisition-context value from the tree hash; cases that model
missing source provenance override it explicitly in `scan_context`. This
context value is not used as the corpus identity. `scanner_implementation_sha256`
identifies the scanner and trust-score source actually executed, including
uncommitted changes. `security_fingerprint` hashes all security results while
excluding duration and peak-memory measurements, which naturally vary between
runs.

## Label meanings

`labels-v2.json` is validated against `schema-v2.json` before scanning.

- `ground_truth` distinguishes plain benign code, intentional benign
  capabilities, malicious behavior, and behavior that needs deployment context.
- `raw_rules` is the set of detector IDs that should fire. Empty means that a
  capability or documentation example must not become a vulnerability finding.
- `root_issues` groups overlapping rules that describe one underlying issue.
  A root can label its expected `kind`, `disposition`, and
  `effective_severity`.
- `forbidden_effective_severities` is most useful for benign cases. A finding
  uses `effective_severity` when present and otherwise falls back to legacy
  `severity`.
- `capabilities` records semantic behavior separately from vulnerabilities.
- `security_grade` is an allowed set of final grades under the fixed scoring
  context.
- `manual_review` is `required`, `not_required`, or `either`.
- `enforcement` is either `blocking` or `observe`.

For legacy scan reports, a missing `root_cause_id` falls back to the finding ID
for grouping. Random finding IDs are rendered as stable `legacy-root-NNN`
aliases in output. Missing `kind` and `disposition` are reported as
`legacy_unknown`; they are never silently treated as the desired v2 value.

## Metrics

The runner emits:

- micro precision/recall by raw rule and overall;
- root-issue precision/recall after matching roots by explicit ID or rule
  overlap;
- the fraction of benign/benign-capability cases with a high or critical
  finding;
- the fraction of malicious cases detected at high or critical severity;
- a root-level severity confusion matrix, including `none` for missed and
  unexpected roots;
- final grade distribution;
- incomplete-scan and rule-exception ratios; and
- a registry-derived detector coverage table with positive, negative, context,
  true-positive, false-positive, false-negative, and coverage-status fields;
- per-case duration, aggregate duration, and peak traced memory.

Both blocking and observe cases contribute to metrics. Enforcement controls CI
behavior, not measurement. `labels-v2.json` also pins minimum corpus sizes,
minimum raw/root precision and recall, a maximum benign high/critical
false-positive rate, and a minimum malicious high/critical recall. This makes
quality regression measurable even when individual detector rules still fire.

`coverage-v2.json` maps every detector in
`scanners.risk_scanner.rule_runner.RULE_SPECS` to explicit positive and
rule-specific benign near-miss cases. Only those listed near-misses contribute
to detector-level false positives; unrelated benign cases are not mechanically
reused. A rule without a positive is `untested`, and one without a related
negative is `incomplete`; either state fails `--check`. `SR-005b` also has an
independent AST alias case that forbids an `SR-005` result.

The complete corpus intentionally does not disguise failure injection as a
successful scan. `apps/api/tests/test_benchmark_resilience.py` keeps a separate
static resilience matrix for malformed metadata, nested fixtures with parent
files, symlinks, file/directory limits, rule exceptions, OSV no-result/failure/
query-limit responses, and unavailable or timed-out LLM review. Its expected
contract is: a deterministic OSV no-result is complete/benign; malformed
metadata is an SR-010 finding but remains complete; external symlinks, resource
limits, rule exceptions, OSV failures/limits, and review timeouts are explicit
partial or inconclusive states. Injecting any partial or exception result into
the blocking v2 benchmark must fail its coverage gate.

## Human annotation workflow

1. Reduce the behavior to the smallest package that preserves the relevant
   source, sink, and security boundary. Do not add an actual secret or runnable
   destructive payload.
2. Record whether it is synthetic or minimized from another source, the exact
   source path/reference and revision, its license, and a concrete annotation
   explaining the trust boundary.
3. Label the desired security behavior independently of current scanner output.
   In particular, do not add an observed false-positive rule to `raw_rules` just
   to make a case pass.
4. Put a new or unresolved behavior in `observe` with its follow-up PR. Use
   `blocking` only after the current implementation satisfies the reviewed
   target. Fault-injection cases for OSV failure/limits, timeouts, rule
   exceptions, and unavailable LLM fallback belong in resilience tests rather
   than the all-complete main corpus.
5. Insert a temporary 64-zero content hash, run without `--check`, copy the
   case's reported `actual.content_tree_sha256`, and review the diff before
   replacing the placeholder.
6. Run the focused benchmark tests and both benchmark commands. Re-run once and
   confirm `security_fingerprint` is unchanged.

When behavior is fixed, update only the labels whose human target changed,
remove the resolved `known_gap`, switch them to `blocking`, and retain the case
so a malicious contrast variant cannot regress while a benign false positive is
being removed.

## Corpus layout and provenance

`corpus/benign-code` contains the benign controls and rule-specific near-misses;
`corpus/malicious-code` contains deterministic security positives; and
`corpus/needs-context` covers operator-controlled or deployment-dependent
behavior. Five original two-sided
families under `corpus/contrast-pairs` vary only the decisive source or sink:

- loopback bind versus public bind;
- operator environment versus request query;
- Origin comparison versus `fetch(origin)`;
- package-owned state versus a user-controlled deletion path; and
- a generated session token versus a third-party GitHub token.

The brainstorming launcher is minimized from the in-repository Superpowers
fixture at the recorded revision and remains MIT licensed. The webapp-testing
and MCP-builder examples are minimized from Apache-2.0 in-repository fixtures.
All other samples are original synthetic fixtures licensed Apache-2.0 with this
repository. The per-case source record is authoritative; keep it updated when a
fixture changes. Required attribution and license notices are collected in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Interface for follow-up PRs

Scanner findings may provide `root_cause_id`, `kind`, `disposition`, and
`effective_severity`; the runner groups findings that share a root ID. Semantic
classification and LLM adjudication changes should update implementation first,
then change labels only when human ground truth actually changes. Aggregate
quality gates remain stable unless a reviewed benchmark-policy change explicitly
updates them.
