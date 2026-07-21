"""
Layer 2: Intent Assessment

I1 — Permission Reasonability: checks whether declared permissions match the package
     type and described functionality.
I2 — Prompt Safety: evaluates scan-report findings for dangerous patterns.
I3 — Behavior Consistency: cross-validates I1 against I2 to detect deception or
     overreaching.

All functions operate on plain dicts and return dict results.
Uses only the Python standard library.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Well-known package types and their typical permission profiles
# ---------------------------------------------------------------------------

# For each package type, define what constitutes "reasonable" vs "excessive" permissions.
# skill: usually needs filesystem r/w and limited shell; network only for API-based skills
# mcp_server: varies by function; database access, network are expected for many
# command: often needs shell and filesystem; broader permissions may be acceptable
# plugin: aggregates other types; depends on components
# subagent: similar to skill but may have broader tool access
# prompt: typically minimal — usually just filesystem read for template loading

_EXPECTED_FILESYSTEM_SCOPE: dict[str, bool] = {
    # True means broad filesystem access is expected/normal for this type
    "skill": False,
    "mcp_server": False,
    "plugin": True,  # plugins aggregate; may need broader access
    "subagent": False,
    "command": True,  # commands often need broad access
    "prompt": False,
}

# ---------------------------------------------------------------------------
# Danger signals for permission assessment
# ---------------------------------------------------------------------------

_DANGEROUS_CATEGORIES = frozenset({
    "prompt_injection",
    "dangerous_shell",
    "credential_access",
    "hardcoded_secret",
    "remote_code_execution",
    "supply_chain",
    "output_handling",
    "system_prompt_leakage",
    "memory_poisoning",
    "ssrf",
    "agent_snooping",
    "tool_misuse",
})


def _is_broad_path(path: str) -> bool:
    """Check if a path pattern represents broad access (root, home, wildcard)."""
    broad_patterns = ("/", "~/", "~", "*", "**")
    stripped = path.strip()
    if stripped in broad_patterns:
        return True
    if stripped.endswith("/*") or stripped.endswith("/**"):
        return True
    return False


def _count_danger_signals(permissions: dict[str, Any], package_type: str) -> tuple[int, list[str]]:
    """Count dangerous permission signals and return (count, evidence_list)."""
    signals: list[str] = []
    count = 0

    filesystem: dict[str, Any] = permissions.get("filesystem", {}) or {}
    shell: dict[str, Any] = permissions.get("shell", {}) or {}
    network: dict[str, Any] = permissions.get("network", {}) or {}
    environment: dict[str, Any] = permissions.get("environment", {}) or {}
    credentials: dict[str, Any] = permissions.get("credentials", {}) or {}

    # 1. filesystem.delete = true
    if filesystem.get("delete", False):
        count += 1
        signals.append("Allows file deletion")

    # 2. Broad filesystem read
    read_paths: list[str] = filesystem.get("read", []) or []
    if any(_is_broad_path(p) for p in read_paths):
        count += 1
        signals.append("Broad filesystem read access (/, ~/, or wildcard)")

    # 3. Broad filesystem write
    write_paths: list[str] = filesystem.get("write", []) or []
    if any(_is_broad_path(p) for p in write_paths):
        count += 1
        signals.append("Broad filesystem write access (/, ~/, or wildcard)")

    # 4. Shell allowed without command whitelist
    if shell.get("allowed", False):
        commands: list[str] = shell.get("commands", []) or []
        if not commands:
            count += 1
            signals.append("Shell access allowed with no command whitelist (any command)")
        elif len(commands) > 20:
            count += 1
            signals.append("Excessively large shell command whitelist")

    # 5. Network allowed without domain whitelist
    if network.get("allowed", False):
        domains: list[str] = network.get("domains", []) or []
        if not domains:
            count += 1
            signals.append("Network access allowed with no domain whitelist (any domain)")

    # 6. Environment variable write
    env_write: list[str] = environment.get("write", []) or []
    if env_write:
        count += 1
        signals.append(f"Can write environment variables: {env_write}")

    # 7. Broad environment read
    env_read: list[str] = environment.get("read", []) or []
    if "*" in env_read or "**" in env_read:
        count += 1
        signals.append("Can read all environment variables (wildcard)")

    # 8. Credential access
    cred_access: list[str] = credentials.get("access", []) or []
    if cred_access:
        count += 1
        signals.append(f"Requests credential access: {cred_access}")

    # 9. Database access (may be normal for mcp_server, flag for others)
    database: dict[str, Any] = permissions.get("database", {}) or {}
    if database.get("allowed", False) and package_type != "mcp_server":
        count += 1
        signals.append("Requests database access (unexpected for package type)")

    # 10. Browser access (unusual for most types)
    browser: dict[str, Any] = permissions.get("browser", {}) or {}
    if browser.get("allowed", False) and package_type not in ("plugin",):
        count += 1
        signals.append("Requests browser access")

    return count, signals


def assess_permission_reasonability(package_metadata: dict[str, Any]) -> dict[str, Any]:
    """I1: Assess whether declared permissions are reasonable for the package type.

    Levels:
        minimal    — tightly scoped permissions appropriate for the type
        acceptable — reasonable permissions; no concerning signals
        excessive  — more permissions than needed for the type
        dangerous  — clearly dangerous permission combinations

    Args:
        package_metadata: dict conforming to agent-package.schema.json

    Returns:
        dict with keys: level (str), score (int 0-100), evidence (list[str]),
                        danger_count (int)
    """
    permissions: dict[str, Any] = package_metadata.get("permissions", {}) or {}
    package_type: str = package_metadata.get("type", "unknown")

    danger_count, signals = _count_danger_signals(permissions, package_type)

    # Count total declared permission categories
    perm_categories = 0
    for key in ("filesystem", "shell", "network", "environment",
                "credentials", "database", "browser", "external_services"):
        val = permissions.get(key)
        if val:
            if isinstance(val, dict) and val:
                # Check if it has meaningful content beyond empty dict
                has_content = False
                for sub_k, sub_v in val.items():
                    if sub_v:  # non-empty
                        if isinstance(sub_v, bool):
                            if sub_v:
                                has_content = True
                        elif isinstance(sub_v, list):
                            if len(sub_v) > 0:
                                has_content = True
                        else:
                            has_content = True
                if has_content:
                    perm_categories += 1
            elif isinstance(val, list) and val:
                perm_categories += 1

    evidence: list[str] = []

    if danger_count == 0:
        level = "minimal"
        evidence.append("Permissions are tightly scoped with no danger signals")
    elif danger_count <= 2:
        level = "acceptable"
        evidence.append(f"Permissions have {danger_count} minor concern(s)")
        evidence.extend(signals)
    elif danger_count <= 7:
        level = "excessive"
        evidence.append(f"Permissions have {danger_count} concerning signals — excessive for type '{package_type}'")
        evidence.extend(signals)
    else:
        level = "dangerous"
        evidence.append(f"Permissions have {danger_count} danger signals — highly dangerous combination")
        evidence.extend(signals)

    # Score: starts at 100, subtract per danger signal
    score = max(5, 100 - danger_count * 20)

    # Also penalize for too many permission categories without good reason
    if perm_categories >= 5:
        score = max(5, score - 10)
        evidence.append(f"Declares {perm_categories} permission categories (high)")

    return {
        "level": level,
        "score": score,
        "evidence": evidence,
        "danger_count": danger_count,
    }


def assess_prompt_safety(
    package_metadata: dict[str, Any],
    scan_report: dict[str, Any] | None,
) -> dict[str, Any]:
    """I2: Evaluate scan findings for prompt and code safety.

    Levels:
        safe       — no critical/high findings, clean scan
        suspicious — medium/low findings present, or missing scan report
        dangerous  — critical or high findings in dangerous categories

    Args:
        package_metadata: dict conforming to agent-package.schema.json
        scan_report: dict conforming to scan-report.schema.json, or None if no scan

    Returns:
        dict with keys: level (str), score (int 0-100), evidence (list[str]),
                        critical_count (int), high_count (int), medium_count (int),
                        low_count (int)
    """
    if scan_report is None:
        return {
            "level": "suspicious",
            "score": 50,
            "evidence": ["No scan report available — safety cannot be verified"],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "scan_available": False,
        }

    summary: dict[str, Any] = scan_report.get("summary", {}) or {}
    findings: list[dict[str, Any]] = scan_report.get("findings", []) or []

    critical_count: int = summary.get("critical", 0)
    high_count: int = summary.get("high", 0)
    medium_count: int = summary.get("medium", 0)
    low_count: int = summary.get("low", 0)

    evidence: list[str] = []

    # Check for dangerous-category findings at critical/high severity
    dangerous_findings: list[str] = []
    for f in findings:
        severity = f.get("severity", "")
        category = f.get("category", "")
        if severity in ("critical", "high") and category in _DANGEROUS_CATEGORIES:
            dangerous_findings.append(
                f"[{severity}] {f.get('title', 'Unknown')} ({category})"
            )

    if dangerous_findings:
        level = "dangerous"
        evidence.append(
            f"Found {len(dangerous_findings)} critical/high finding(s) in dangerous categories"
        )
        evidence.extend(dangerous_findings)
        score = max(0, 20 - len(dangerous_findings) * 5)
        return {
            "level": level,
            "score": score,
            "evidence": evidence,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "scan_available": True,
        }
    elif critical_count > 0 or high_count > 0:
        # Critical/high but not in the most dangerous categories
        level = "suspicious"
        evidence.append(
            f"Found {critical_count} critical, {high_count} high finding(s) "
            f"(non-dangerous categories)"
        )
        score = 50
        return {
            "level": level,
            "score": score,
            "evidence": evidence,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "scan_available": True,
        }
    elif medium_count > 2 or low_count > 5:
        level = "suspicious"
        evidence.append(f"Multiple medium/low findings: {medium_count} medium, {low_count} low")
        score = 60
        return {
            "level": level,
            "score": score,
            "evidence": evidence,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "scan_available": True,
        }
    else:
        level = "safe"
        total_findings = critical_count + high_count + medium_count + low_count
        if total_findings == 0:
            evidence.append("Scan is clean — no findings")
        else:
            evidence.append(
                f"Only {total_findings} minor finding(s): "
                f"{medium_count} medium, {low_count} low"
            )
        score = max(85, 100 - total_findings * 3)
        return {
            "level": level,
            "score": score,
            "evidence": evidence,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "scan_available": True,
        }


def assess_behavior_consistency(
    i1_result: dict[str, Any],
    i2_result: dict[str, Any],
) -> dict[str, Any]:
    """I3: Cross-validate permission reasonability (I1) against prompt safety (I2).

    Detects packages that declare innocent-looking permissions but have dangerous
    scan findings (deceptive), or that over-declare permissions relative to what
    the scan reveals (overreaching).

    Levels:
        consistent  — I1 and I2 align well; permissions match scan results
        gap         — missing scan report; cannot validate consistency
        overreaching — permissions are broader than what the scan suggests is needed
        deceptive   — scan shows dangerous content but permissions look minimal
        malicious   — both permissions and scan findings are dangerous

    Args:
        i1_result: result dict from assess_permission_reasonability()
        i2_result: result dict from assess_prompt_safety()

    Returns:
        dict with keys: level (str), score (int 0-100), evidence (list[str])
    """
    i1_level: str = i1_result.get("level", "acceptable")
    i2_level: str = i2_result.get("level", "safe")
    evidence: list[str] = []

    # Map levels to numeric for comparison
    i1_rank = {"minimal": 0, "acceptable": 1, "excessive": 2, "dangerous": 3}
    i2_rank = {"safe": 0, "suspicious": 1, "dangerous": 2}

    i1_val = i1_rank.get(i1_level, 1)
    i2_val = i2_rank.get(i2_level, 1)

    # Gap: missing scan report — detected via explicit sentinel flag
    if not i2_result.get("scan_available", True):
        level = "gap"
        score = 55
        evidence.append("No scan report available — cannot cross-validate I1 vs I2")
        return {"level": level, "score": score, "evidence": evidence}

    # Malicious: both are at maximum danger
    if i1_level == "dangerous" and i2_level == "dangerous":
        level = "malicious"
        score = 3
        evidence.append(
            "Both permissions and scan findings indicate malicious intent: "
            f"I1={i1_level}, I2={i2_level}"
        )
        return {"level": level, "score": score, "evidence": evidence}

    # Deceptive: I2 is dangerous but I1 looks acceptable/minimal (hiding intent)
    if i2_level == "dangerous" and i1_level in ("minimal", "acceptable"):
        level = "deceptive"
        score = 8
        evidence.append(
            f"Deceptive package: scan shows dangerous content (I2={i2_level}) "
            f"but permissions appear innocent (I1={i1_level})"
        )
        return {"level": level, "score": score, "evidence": evidence}

    # Overreaching: I1 is excessive/dangerous but I2 is safe (declares more than needed)
    if i1_level in ("excessive", "dangerous") and i2_level == "safe":
        level = "overreaching"
        score = 45
        evidence.append(
            f"Permissions are broader than scan findings suggest: "
            f"I1={i1_level} vs I2={i2_level}"
        )
        return {"level": level, "score": score, "evidence": evidence}

    # Suspicious + excessive: I1 is excessive/dangerous and I2 is suspicious —
    # concerning combination that should not fall through to "consistent".
    if i1_level in ("excessive", "dangerous") and i2_level == "suspicious":
        level = "overreaching"
        score = 50
        evidence.append(
            f"Permissions are broader than expected AND scan is suspicious: "
            f"I1={i1_level} vs I2={i2_level}"
        )
        return {"level": level, "score": score, "evidence": evidence}

    # Consistent: everything aligns
    level = "consistent"
    score = 90
    evidence.append(f"Permissions (I1={i1_level}) are consistent with scan results (I2={i2_level})")

    # Slightly lower score if consistent but both are suspicious
    if i2_level == "suspicious":
        score = 70

    return {"level": level, "score": score, "evidence": evidence}
