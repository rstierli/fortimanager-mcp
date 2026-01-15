"""Tests for configuration management."""

import pytest
from fortimanager_mcp.utils.config import Settings


class TestSettings:
    """Test Settings class."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        settings = Settings()
        assert settings.fortimanager_port == 443
        assert settings.fortimanager_verify_ssl is False
        assert settings.fortimanager_timeout == 30
        assert settings.fmg_tool_mode == "full"

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variable override."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.setenv("FORTIMANAGER_PORT", "8443")

        settings = Settings()
        assert settings.fortimanager_host == "test-fmg.example.com"
        assert settings.fortimanager_port == 8443
