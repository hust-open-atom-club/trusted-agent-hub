"""Regression tests for pytest's dedicated database opt-in configuration."""

import os
import runpy
from pathlib import Path

import dotenv
import pytest


DATABASE_ENVIRONMENT_KEYS = (
    "DATABASE_URL",
    "DATABASE_DRIVER",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
)
CONFTEST_PATH = Path(__file__).with_name("conftest.py")


def _prepare_normal_database_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for database_key in DATABASE_ENVIRONMENT_KEYS:
        monkeypatch.setenv(database_key, "must-not-be-used-by-tests")
    monkeypatch.setenv("TRUSTED_AGENT_HUB_SKIP_DOTENV", "false")


def test_root_env_test_url_is_exported_for_integration_skip_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_database_url = "postgresql://tester@localhost/trusted_agent_hub_test"
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    _prepare_normal_database_environment(monkeypatch)
    monkeypatch.setattr(
        dotenv,
        "dotenv_values",
        lambda _path: {"TEST_DATABASE_URL": f"  {test_database_url}  "},
    )

    runpy.run_path(str(CONFTEST_PATH), run_name="_issue_90_conftest")

    assert os.environ["TEST_DATABASE_URL"] == test_database_url
    assert os.environ["DATABASE_URL"] == test_database_url
    for database_key in DATABASE_ENVIRONMENT_KEYS[1:]:
        assert os.environ[database_key] == ""


def test_missing_test_url_never_reuses_normal_database_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_DATABASE_URL", "  ")
    _prepare_normal_database_environment(monkeypatch)
    monkeypatch.setattr(
        dotenv,
        "dotenv_values",
        lambda _path: {"TEST_DATABASE_URL": ""},
    )

    runpy.run_path(str(CONFTEST_PATH), run_name="_issue_90_conftest")

    assert "TEST_DATABASE_URL" not in os.environ
    for database_key in DATABASE_ENVIRONMENT_KEYS:
        assert os.environ[database_key] == ""
