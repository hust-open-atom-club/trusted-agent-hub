"""Type-based install-client constraint tests."""

from __future__ import annotations

import pytest

from schema.constants import PACKAGE_TYPE_INSTALL_CLIENTS
from src.services.producer import ProducerService, ProducerServiceError
from src.services.producer import _validate_install_readiness


def test_plugin_type_allows_only_plugin_client() -> None:
    assert PACKAGE_TYPE_INSTALL_CLIENTS["plugin"] == ("claude-code-plugin",)


def test_skill_type_allows_skill_clients_only() -> None:
    assert PACKAGE_TYPE_INSTALL_CLIENTS["skill"] == (
        "claude-code",
        "cursor",
    )


def test_normalize_rejects_plugin_cursor_install() -> None:
    with pytest.raises(ProducerServiceError):
        ProducerService._normalize_compatibility(
            "plugin", ["claude-code", "cursor"]
        )


def test_normalize_rejects_skill_plugin_install() -> None:
    with pytest.raises(ProducerServiceError):
        ProducerService._normalize_compatibility(
            "skill", ["claude-code-plugin"]
        )


def test_normalize_defaults_to_type_clients() -> None:
    assert ProducerService._normalize_compatibility("plugin", None) == [
        "claude-code-plugin"
    ]
    assert ProducerService._normalize_compatibility("skill", []) == [
        "claude-code",
        "cursor",
    ]


def test_install_readiness_flags_type_incompatible_clients() -> None:
    version = {
        "compatibility": ["claude-code", "cursor"],
        "permissions": {},
        "installation": {
            "method": "copy_directory",
            "target_client": "claude-code",
            "steps": [{"action": "download"}],
        },
        "trust_score": {
            "risk_summary": {
                "grade": "A",
            }
        },
    }
    missing = _validate_install_readiness(version, "plugin")
    assert any("compatibility" in item for item in missing)


def test_install_readiness_accepts_type_compatible_clients() -> None:
    version = {
        "compatibility": ["claude-code-plugin"],
        "permissions": {},
        "installation": {
            "method": "copy_directory",
            "target_client": "claude-code-plugin",
            "steps": [{"action": "download"}],
        },
        "trust_score": {
            "risk_summary": {
                "grade": "A",
            }
        },
    }
    missing = _validate_install_readiness(version, "plugin")
    assert not any("compatibility" in item for item in missing)
