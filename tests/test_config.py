"""Tests for configuration management."""

import pytest

from fortimanager_mcp.utils.config import Settings


class TestSettings:
    """Test Settings class."""

    def test_settings_load(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that settings load correctly."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")

        settings = Settings()
        # Test that settings object is created and has expected attributes
        assert settings.FORTIMANAGER_HOST == "test-fmg.example.com"
        assert hasattr(settings, "FORTIMANAGER_VERIFY_SSL")
        assert hasattr(settings, "FORTIMANAGER_TIMEOUT")
        assert hasattr(settings, "FMG_TOOL_MODE")
        assert settings.FMG_TOOL_MODE in ("full", "dynamic")

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable override."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "override-fmg.example.com")
        monkeypatch.setenv("FORTIMANAGER_TIMEOUT", "60")

        settings = Settings()
        assert settings.FORTIMANAGER_HOST == "override-fmg.example.com"
        assert settings.FORTIMANAGER_TIMEOUT == 60

    def test_host_validator_strips_protocol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that host validator strips protocol prefix."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "https://fmg.example.com/")

        settings = Settings()
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"
