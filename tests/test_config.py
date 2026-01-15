"""Tests for configuration management."""

import pytest

from fortimanager_mcp.utils.config import Settings


class TestSettings:
    """Test Settings class."""

    def test_default_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test default configuration values."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        settings = Settings()
        assert settings.FORTIMANAGER_VERIFY_SSL is True
        assert settings.FORTIMANAGER_TIMEOUT == 30
        assert settings.FMG_TOOL_MODE == "full"

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable override."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "override-fmg.example.com")
        monkeypatch.setenv("FORTIMANAGER_TIMEOUT", "60")

        settings = Settings()
        assert settings.FORTIMANAGER_HOST == "override-fmg.example.com"
        assert settings.FORTIMANAGER_TIMEOUT == 60
