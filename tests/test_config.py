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

    def test_stateless_http_defaults_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stateless HTTP is opt-in: default preserves stateful session behavior."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.delenv("MCP_STATELESS_HTTP", raising=False)

        settings = Settings()
        assert settings.MCP_STATELESS_HTTP is False

    def test_stateless_http_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MCP_STATELESS_HTTP=true enables stateless streamable-HTTP transport."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.setenv("MCP_STATELESS_HTTP", "true")

        settings = Settings()
        assert settings.MCP_STATELESS_HTTP is True

    def test_allowed_hosts_comma_separated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Comma-separated MCP_ALLOWED_HOSTS parses instead of crashing settings load."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.setenv("MCP_ALLOWED_HOSTS", "mcp.example.com, alt.example.com:8000")

        settings = Settings()
        assert settings.MCP_ALLOWED_HOSTS == ["mcp.example.com", "alt.example.com:8000"]

    def test_allowed_hosts_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """JSON-array MCP_ALLOWED_HOSTS (README form) still parses."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.setenv("MCP_ALLOWED_HOSTS", '["mcp.example.com", "10.1.5.62:*"]')

        settings = Settings()
        assert settings.MCP_ALLOWED_HOSTS == ["mcp.example.com", "10.1.5.62:*"]

    def test_allowed_hosts_single_value_and_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A single bare host works; an empty value means no extra hosts."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")

        monkeypatch.setenv("MCP_ALLOWED_HOSTS", "10.1.5.62:*")
        assert Settings().MCP_ALLOWED_HOSTS == ["10.1.5.62:*"]

        monkeypatch.setenv("MCP_ALLOWED_HOSTS", "")
        assert Settings().MCP_ALLOWED_HOSTS == []
