# Security and evidence assessment model

TrustedAgentHub reports two independent indicators because unsafe behavior and
missing corroborating evidence are different questions.

## Security assessment

`security_assessment` is the policy-driving result. Its score and A–E grade use
declared/observed permission risk, static scanner findings, behavior consistency,
scan completeness, and explicit manual security review decisions. A finding that
still needs semantic review can cap the automatic conclusion at review-required;
only confirmed malicious evidence or a rejected security review can force the
blocked result.

The compatibility fields `score`, `risk_summary.level`, and
`risk_summary.grade` mirror this security assessment. Evidence metadata does not
silently change them.

## Evidence assessment

`evidence_assessment` reports provenance, verified artifact proofs, metadata,
version information, review coverage, author reputation, and user feedback. It
contains both a quality score and a coverage ratio. Only available signals enter
the quality-score denominator; unavailable signals reduce coverage instead of
being treated as failed checks.

Signature, attestation, and SBOM states are tri-state:

- `verified`: a configured independent verifier validated the acquired bytes;
- `not_verified`: the verifier ran but validation did not succeed;
- `not_available`: the deployment has no result from that verifier.

Package-authored URLs or claims never become independent verification facts.
When a verifier is unavailable the scanner emits one informational advisory and
does not apply the historical fixed deduction.

## Advisory compatibility

Existing advisory `deduction` values remain in scan reports for audit and UI
migration. The stored scoring audit records their sum as
`score_breakdown.unapplied_advisory_points`; `advisory_deduction` is zero and the
points do not alter the security score or grade. High-priority security
advisories can still require manual review or explicit installation
confirmation.

## Regression policy

The labeled benchmark combines normal executable packages, needs-context cases,
malicious packages, and contrast pairs. `quality_gates` fail CI when aggregate
precision/recall, benign high/critical false-positive rate, malicious
high/critical recall, or minimum corpus sizes regress. This measures outcomes,
not merely whether a rule matched some text.
