"""Shared Markdown frontmatter parser regression tests."""

from packages.schema.frontmatter import parse_frontmatter, split_frontmatter


def test_block_scalar_description_is_preserved() -> None:
    result = parse_frontmatter(
        "---\n"
        "name: humanizer-demo\n"
        "description: |\n"
        "  first line\n"
        "  second line\n"
        "---\n"
        "# body\n"
    )

    assert result.error is None
    assert result.data["description"] == "first line\nsecond line"


def test_indented_yaml_separator_is_not_a_frontmatter_delimiter() -> None:
    result = parse_frontmatter(
        "---\n"
        "description: |\n"
        "  ---\n"
        "  content\n"
        "---\n"
    )

    assert result.error is None
    assert result.data["description"] == "---\ncontent"


def test_malformed_frontmatter_returns_actionable_error() -> None:
    result = parse_frontmatter("---\nname: demo\n")

    assert result.present is True
    assert result.data == {}
    assert result.error is not None


def test_split_frontmatter_uses_yaml_delimiter_for_body() -> None:
    result, body = split_frontmatter(
        "---\nname: demo\ndescription: |\n  body has --- text\n---\n# Heading\n"
    )

    assert result.error is None
    assert body == "# Heading\n"
