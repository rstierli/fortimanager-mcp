"""Masking configuration: off by default, key optional, resolved from env.

Masking is opt-in (issue #34 / FAZ RFC #40). A deployment that does not ask
for it must never pay for it, and one that does ask must supply a key.
"""

import pytest

from fortimanager_mcp.utils.config import Settings


def test_masking_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    monkeypatch.delenv("MASKING_ENABLED", raising=False)
    monkeypatch.delenv("FMG_MASKING_KEY", raising=False)

    settings = Settings()

    assert settings.MASKING_ENABLED is False
    assert settings.FMG_MASKING_KEY is None


def test_masking_flag_and_key_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    monkeypatch.setenv("MASKING_ENABLED", "true")
    monkeypatch.setenv("FMG_MASKING_KEY", "2DE79D232DF5585D68CE47882AE256D6")

    settings = Settings()

    assert settings.MASKING_ENABLED is True
    assert settings.FMG_MASKING_KEY == "2DE79D232DF5585D68CE47882AE256D6"
