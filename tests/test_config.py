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


class TestSafetyDefaultsAreShippedStrict:
    """The shipped default of every safety gate, pinned.

    upstream #69: flipping FMG_SCRIPT_SAFETY's default from strict to
    disabled left the whole suite green, because every script-safety test
    sets the env var explicitly and so never exercises the default anyone
    actually deploys with. The same held for the other five.

    Read off the model rather than a constructed instance so a stray env
    var or a developer's .env cannot make this pass by accident.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "FMG_SCRIPT_SAFETY",
            "FMG_RESTORE_SAFETY",
            "FMG_REVERT_SAFETY",
            "FMG_FIRMWARE_SAFETY",
            "FMG_POLICY_SAFETY",
            "FMG_INSTALL_SAFETY",
        ],
    )
    def test_shipped_default_is_strict(self, name: str) -> None:
        assert Settings.model_fields[name].default == "strict", (
            f"{name} ships defaulting to "
            f"{Settings.model_fields[name].default!r}, not 'strict'. A gate "
            f"that is off unless someone opts in is not a gate."
        )

    def test_a_deployment_with_no_env_overrides_gets_strict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The model default is only the shipped value if nothing in the
        settings machinery overrides it on the way out."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        for name in (
            "FMG_SCRIPT_SAFETY",
            "FMG_RESTORE_SAFETY",
            "FMG_REVERT_SAFETY",
            "FMG_FIRMWARE_SAFETY",
            "FMG_POLICY_SAFETY",
            "FMG_INSTALL_SAFETY",
        ):
            monkeypatch.delenv(name, raising=False)

        settings = Settings(_env_file=None)

        assert settings.FMG_SCRIPT_SAFETY == "strict"
        assert settings.FMG_RESTORE_SAFETY == "strict"
        assert settings.FMG_REVERT_SAFETY == "strict"
        assert settings.FMG_FIRMWARE_SAFETY == "strict"
        assert settings.FMG_POLICY_SAFETY == "strict"
        assert settings.FMG_INSTALL_SAFETY == "strict"
