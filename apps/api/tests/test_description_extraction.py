"""Description regressions for wrapped Markdown in scanned packages."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.schema.extract_skills import extract_single_skill, first_paragraph
from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from src.routers import trust


# Exact README from beibainian/package at
# a21b461ccad3ee11749f1eabff4c84c455b7517a/test-tool-poisoning-mcp/README.md,
# also verified against the locally scanned artifact and source snapshot.
UPSTREAM_README = (
    "# Tool-Poisoning MCP Server\n"
    "\n"
    "Security-test fixture for MCP tool-description and hidden-tool detection. The\n"
    "tool bodies return fixed values and are never invoked.\n"
)
UPSTREAM_DESCRIPTION = (
    "Security-test fixture for MCP tool-description and hidden-tool detection. "
    "The tool bodies return fixed values and are never invoked."
)


@pytest.mark.parametrize("metadata_path", ["extractor", "scanner"])
def test_wrapped_upstream_readme_reaches_package_metadata(
    tmp_path: Path, metadata_path: str,
) -> None:
    package_dir = tmp_path / "test-tool-poisoning-mcp"
    package_dir.mkdir()
    (package_dir / "README.md").write_text(UPSTREAM_README, encoding="utf-8")
    # The upstream manifest declares a different description. Keep the existing
    # README fallback precedence; only repair the loss at its physical line wrap.
    (package_dir / "manifest.json").write_text(
        json.dumps({
            "name": "test-tool-poisoning-mcp",
            "type": "mcp_server",
            "description": (
                "A static MCP fixture for hidden tools and poisoned tool descriptions."
            ),
        }),
        encoding="utf-8",
    )
    source = {
        "repo_url": "https://github.com/beibainian/package",
        "subdirectory": "test-tool-poisoning-mcp",
    }

    if metadata_path == "scanner":
        policy = ScanPolicy()
        inventory = build_inventory(package_dir, policy)
        contents = load_text_files(inventory, policy=policy)
        metadata = trust._build_package_metadata(
            {}, str(package_dir), **source,
            policy=policy, inventory=inventory, file_contents=contents,
        )
    else:
        metadata = extract_single_skill(package_dir, **source)

    assert metadata["description"] == UPSTREAM_DESCRIPTION
    assert len(metadata["description"]) == 132
    assert metadata["type"] == "mcp_server"


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_paragraph_skips_frontmatter_heading_and_badges(newline: str) -> None:
    text = newline.join([
        "---", "name: wrapped-description", "---", "# Package", "",
        "[![Build](badge.svg)](https://example.com/build)", "",
        "A description with a soft", "  line break and trailing spaces.  ",
    ])

    assert first_paragraph(text) == (
        "A description with a soft line break and trailing spaces."
    )


@pytest.mark.parametrize("following_block", [
    "\nA separate paragraph.",
    "## Installation\nInstall commands.",
    "- Install the package.",
    "1. Install the package.",
    "> A separate quotation.",
    "```sh\ninstall-command\n```",
    "~~~sh\ninstall-command\n~~~",
    "---\nA separate section.",
])
def test_wrapped_paragraph_stops_before_another_block(following_block: str) -> None:
    text = "A package that reads\nlocal notes.\n" + following_block

    assert first_paragraph(text) == "A package that reads local notes."


def test_wrapped_paragraph_keeps_link_at_start_of_continuation() -> None:
    text = "A package for\n[local notes](https://example.com/notes).\n"

    assert first_paragraph(text) == (
        "A package for [local notes](https://example.com/notes)."
    )


@pytest.mark.parametrize("max_len", [80, 200])
def test_description_limit_is_applied_after_joining_lines(max_len: int) -> None:
    text = "A wrapped description.\n" + "More details. " * 30
    expected = "A wrapped description. " + "More details. " * 30

    assert first_paragraph(text, max_len) == expected[:max_len]
    assert len(first_paragraph(text, max_len)) == max_len


def test_frontmatter_description_keeps_precedence_and_limit(tmp_path: Path) -> None:
    declared = "Declared description. " * 12
    (tmp_path / "SKILL.md").write_text(
        f"---\nname: explicit-description\ndescription: {declared}\n---\n"
        + UPSTREAM_README,
        encoding="utf-8",
    )

    assert extract_single_skill(tmp_path)["description"] == declared.strip()[:200]


@pytest.mark.parametrize("text", ["", "# Heading\n\n![Badge](badge.svg)\n"])
def test_no_prose_returns_empty_description(text: str) -> None:
    assert first_paragraph(text) == ""
