"""Regression tests for scope-aware destructive permission inference."""

from packages.schema.permission_semantics import analyze_delete_operations


def test_python_delete_scope_distinguishes_own_state_from_request_path() -> None:
    own_state = analyze_delete_operations(
        "cleanup.py",
        """from pathlib import Path
import shutil
state = Path(__file__).parent / ".session-state"
shutil.rmtree(state, ignore_errors=True)
""",
    )
    request_path = analyze_delete_operations(
        "cleanup.py",
        """from pathlib import Path
import shutil
def cleanup(request):
    target = Path(request.query["path"])
    shutil.rmtree(target)
""",
    )

    assert [(item.scope, item.source_control, item.recursive) for item in own_state] == [
        ("package_owned", "package", True)
    ]
    assert [
        (item.scope, item.source_control, item.recursive) for item in request_path
    ] == [("unbounded", "remote_attacker", True)]


def test_javascript_delete_scope_follows_one_hop_assignment() -> None:
    own_state = analyze_delete_operations(
        "cleanup.js",
        """const state = path.join(__dirname, ".cache");
fs.rmSync(state, { recursive: true });
""",
    )
    operator_path = analyze_delete_operations(
        "cleanup.js",
        """const target = process.argv[2];
fs.unlinkSync(target);
""",
    )

    assert (own_state[0].scope, own_state[0].source_control) == (
        "package_owned",
        "package",
    )
    assert (operator_path[0].scope, operator_path[0].source_control) == (
        "unbounded",
        "operator",
    )


def test_shell_rm_scope_distinguishes_local_state_from_operator_argument() -> None:
    operations = analyze_delete_operations(
        "cleanup.sh",
        'rm -rf ".cache"\nrm -f "$1"\n',
    )

    assert [
        (item.scope, item.source_control, item.recursive) for item in operations
    ] == [
        ("package_owned", "package", True),
        ("unbounded", "operator", False),
    ]
