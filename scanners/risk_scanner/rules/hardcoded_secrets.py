"""SR-004: auditable, content-based credential exposure detection."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from scanners.risk_scanner.credentials import CredentialLimitExceeded, classify, find_credentials, mask_literals
from scanners.risk_scanner.redaction import credential_redactions, redact_text


_CONTEXT_RULES = {
    "network_use": re.compile(r"\b(?:fetch|axios|requests|https?|curl|Authorization|Bearer|login|authenticate)\b", re.I),
    "config_write": re.compile(r"\b(?:writeFile|writeFileSync|write_text|write_bytes|setenv|putenv|process\.env|os\.environ)\b|\.write\s*\(", re.I),
}
_ASSERTION = re.compile(r"^\s*(?:assert\s+|(?:expect|assert(?:\.\w+)?|self\.assert\w+)\s*\()", re.M)
_EQUALITY_ASSERTION = re.compile(r"==|\.to(?:Be|Equal|StrictEqual)\s*\(|\b(?:assert\.(?:equal|strictEqual)|self\.assertEqual)\s*\(")
_LABELS = {
    "credential_format": "凭据格式命中（有效性待核实）", "suspected": "疑似凭据",
    "placeholder": "明确占位值", "test_fixture": "已识别测试 fixture",
    "example": "已识别示例值", "unknown": "用途不明，需人工复核",
}
_MAX_DETAILS = 100


def run(scanner: Any) -> None:
    files = {name: scanner._read_file_content(name) for name in sorted(scanner.scanned_files)}
    get_redactions = getattr(scanner, "get_credential_redactions", None)
    pattern = get_redactions() if callable(get_redactions) else credential_redactions(files.values())
    if pattern.limited:
        # Stop before grouping, per-field context searches and finding creation.
        # RuleRunner records an incomplete scan; output masking fails closed.
        raise CredentialLimitExceeded("credential_literal_limit_exceeded")
    detected = {name: find_credentials(content) for name, content in files.items() if content}
    groups: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for name, matches in detected.items():
        for match in matches:
            groups[match.value].append((name, match))
    if not groups:
        return

    # A scan-local HMAC correlates occurrences without exporting raw prefixes,
    # suffixes, or dictionary-attackable password hashes. The key is not saved.
    fingerprint_key = secrets.token_bytes(32)
    exposures: dict[str, list[dict[str, Any]]] = defaultdict(list)
    contexts: dict[str, set[str]] = defaultdict(set)
    safe_files = {name: redact_text(mask_literals(content, pattern)).splitlines() for name, content in files.items()}
    for name, content in files.items():
        starts = [0] + [m.end() for m in re.finditer("\n", content)]
        lines = content.splitlines()
        assertions = [
            line.split("#", 1)[0].split("//", 1)[0]
            for line in lines if _ASSERTION.match(line)
        ]
        originals = {(m.start, m.end): m for m in detected.get(name, [])}
        # Associate context with literal/field references, never with filenames.
        field_contexts: dict[str, set[str]] = {}
        for match in detected.get(name, []):
            if match.field and match.field not in field_contexts:
                usages = set()
                for ref in re.finditer(r"(?<![\w$])" + re.escape(match.field) + r"(?![\w$])", content):
                    line = bisect_right(starts, ref.start())
                    nearby = "\n".join(lines[max(0, line - 2):line + 2])
                    usages.update(kind for kind, rule in _CONTEXT_RULES.items() if rule.search(nearby))
                field_contexts[match.field] = usages
        for ref in pattern.finditer(content):
            value = ref[0]
            line = bisect_right(starts, ref.start())
            end_line = bisect_right(starts, ref.end() - 1)
            original = originals.get(ref.span())
            field = original.field if original else ""
            nearby = "\n".join(lines[max(0, line - 2):end_line + 2])
            uses = {kind for kind, rule in _CONTEXT_RULES.items() if rule.search(nearby)}
            uses.update(field_contexts.get(field, set()))
            for assertion in assertions:
                # A truthiness check or a comment mentioning the field does
                # not prove a fixed fixture. Require an expected literal.
                if value in assertion and _EQUALITY_ASSERTION.search(assertion):
                    uses.add("test_assertion")
                    break
            contexts[value].update(uses)
            location = {
                "file": name, "line": line, "end_line": end_line,
                "column": ref.start() - starts[line - 1] + 1,
                "end_column": ref.end() - starts[end_line - 1],
            }
            exposures[value].append({
                **location, "field": field or "(literal)",
                "usage": sorted(uses) or ["assignment" if field else "literal"],
                "snippet": "\n".join(safe_files[name][max(0, line - 2):end_line + 1])[:400],
            })

    for value, matches in groups.items():
        items = exposures[value]
        if not items:
            continue
        # Lead with the declaration, while retaining repetitions in prose and
        # other files as additional exposure evidence.
        items.sort(key=lambda item: (item["field"] == "(literal)", item["file"], item["line"], item["column"]))
        rules = {match.rule for _, match in matches}
        classification, severity, confidence, reasons = classify(
            value, rules, contexts[value], len({item["file"] for item in items}) > 1,
        )
        truncated = len(items) > _MAX_DETAILS
        if truncated and severity == "info":
            classification, severity, confidence = "unknown", "medium", 0.4
            reasons.append("evidence_limit")
        digest = hmac.new(fingerprint_key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        # IDs describe public evidence locations, not password hashes. They
        # stay deterministic across scans; the correlation HMAC is scan-local.
        root_material = [
            [redact_text(mask_literals(item["file"], pattern)), item["line"], item["column"], item["end_line"], item["end_column"]]
            for item in items
        ]
        root_digest = hashlib.sha256(json.dumps([sorted(rules), root_material], ensure_ascii=True).encode()).hexdigest()
        identity = f"finding-{root_digest[:12]}"
        credential = {
            "types": sorted({match.type for _, match in matches}),
            "rules": sorted(rules), "classification": classification,
            "confidence": confidence, "fingerprint": f"hmac-sha256:{digest}",
            "reasons": reasons, "matches": items[:_MAX_DETAILS], "truncated": truncated,
        }
        occurrences = [{k: v for k, v in item.items() if k in {
            "file", "line", "end_line", "column", "end_column",
        }} for item in items[:_MAX_DETAILS]]
        scanner._add_finding(
            rule_id="SR-004", severity=severity, category="hardcoded_secret",
            title=f"硬编码密钥: {_LABELS[classification]}",
            description=f"发现 {len(items)} 处相同凭据材料；按一个根因计分。分类依据为内容和使用上下文，不以文件名豁免。",
            location={**occurrences[0], "snippet": items[0]["snippet"]},
            evidence=f"规则: {', '.join(sorted(rules))}; 分类: {classification}; 指纹: hmac-sha256:{digest}",
            remediation=(
                "人工核对凭据来源、使用位置和有效性；疑似真实凭据应撤销或轮换，并迁移到环境变量或密钥管理服务。勿在报告中粘贴原值。"
                if severity != "info" else "已保留脱敏证据；使用明确占位值，避免替换为真实凭据。"
            ),
            cwe_id="CWE-798", kind="informational" if severity == "info" else "context_dependent",
            disposition="confirmed" if severity == "info" else "needs_context",
            requires_manual_review=severity != "info", llm_review_exempt=True,
            sink_kind="credential_exposure", source_kind="literal",
            root_cause_id=f"root-{root_digest[:20]}", finding_id=identity, credential_evidence=credential,
            occurrences={"count": len(items), "items": occurrences, "truncated": truncated},
        )
