from __future__ import annotations

import pytest

from scanners.risk_scanner.llm_reviewer import (
    ANTHROPIC_DEFAULT_MODEL,
    LLMReviewCallError,
    OPENAI_DEFAULT_MODEL,
    _provider_configuration,
)


_LLM_KEYS = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "SKILLSPECTOR_MODEL",
)


def _clear_llm_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _LLM_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_openai_uses_its_provider_default_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_llm_environment(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")

    provider, _, base_url, model = _provider_configuration()

    assert provider == "openai"
    assert base_url == "https://api.openai.com"
    assert model == OPENAI_DEFAULT_MODEL


def test_anthropic_does_not_reuse_openai_base_url_or_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_llm_environment(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openai-proxy.example.com")
    monkeypatch.setenv("SKILLSPECTOR_MODEL", "")

    provider, _, base_url, model = _provider_configuration()

    assert provider == "anthropic"
    assert base_url == "https://api.anthropic.com"
    assert model == ANTHROPIC_DEFAULT_MODEL


def test_shared_model_override_applies_to_the_selected_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_llm_environment(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://anthropic.example.com/")
    monkeypatch.setenv("SKILLSPECTOR_MODEL", "claude-custom")

    provider, _, base_url, model = _provider_configuration()

    assert provider == "anthropic"
    assert base_url == "https://anthropic.example.com/"
    assert model == "claude-custom"


def test_two_llm_providers_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_llm_environment(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")

    with pytest.raises(LLMReviewCallError, match="not both"):
        _provider_configuration()
