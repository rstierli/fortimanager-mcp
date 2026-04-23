"""Tests for script content safety validation."""

from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.utils.config import get_settings
from fortimanager_mcp.utils.validation import validate_script_content

# =============================================================================
# Pure Validation Function Tests
# =============================================================================


class TestValidateScriptContent:
    """Tests for validate_script_content()."""

    def test_safe_config_script(self):
        content = "config system interface\nedit port1\nset ip 10.0.0.1/24\nend"
        assert validate_script_content(content) == []

    def test_safe_execute_ping(self):
        assert validate_script_content("execute ping 8.8.8.8") == []

    def test_safe_execute_backup(self):
        assert validate_script_content("execute backup config ftp") == []

    def test_safe_execute_traceroute(self):
        assert validate_script_content("execute traceroute 1.1.1.1") == []

    # --- Dangerous commands ---

    def test_blocks_execute_factory_reset(self):
        matches = validate_script_content("execute factory-reset")
        assert len(matches) == 1
        assert "factory-reset" in matches[0]

    def test_blocks_exec_factory_reset(self):
        matches = validate_script_content("exec factory-reset")
        assert len(matches) == 1

    def test_blocks_factoryreset_no_hyphen(self):
        matches = validate_script_content("execute factoryreset")
        assert len(matches) >= 1

    def test_blocks_execute_reboot(self):
        matches = validate_script_content("execute reboot")
        assert len(matches) == 1
        assert "reboot" in matches[0]

    def test_blocks_exec_reboot(self):
        matches = validate_script_content("exec reboot")
        assert len(matches) == 1

    def test_blocks_execute_shutdown(self):
        matches = validate_script_content("execute shutdown")
        assert len(matches) == 1
        assert "shutdown" in matches[0]

    def test_blocks_execute_format(self):
        matches = validate_script_content("execute format")
        assert len(matches) == 1
        assert "format" in matches[0]

    def test_blocks_execute_erase_disk(self):
        matches = validate_script_content("execute erase-disk")
        assert len(matches) == 1
        assert "erase-disk" in matches[0]

    def test_blocks_erasedisk_no_hyphen(self):
        matches = validate_script_content("exec erasedisk")
        assert len(matches) == 1

    # --- Case insensitive ---

    def test_case_insensitive_upper(self):
        assert len(validate_script_content("EXECUTE REBOOT")) > 0

    def test_case_insensitive_mixed(self):
        assert len(validate_script_content("Execute Factory-Reset")) > 0

    # --- Multi-command scripts ---

    def test_multiple_dangerous_commands(self):
        content = "exec reboot\nexecute factory-reset"
        matches = validate_script_content(content)
        assert len(matches) >= 2

    def test_dangerous_embedded_in_larger_script(self):
        content = "config system global\nset hostname test\nend\nexecute reboot\n"
        matches = validate_script_content(content)
        assert len(matches) == 1
        assert "reboot" in matches[0]

    def test_safe_word_boundaries(self):
        """Ensure 'execute' in comments or strings doesn't trigger."""
        # The word "reboot" alone without "execute/exec" prefix should not match
        assert validate_script_content("# this will reboot the device") == []
        assert validate_script_content("set description 'reboot window'") == []


# =============================================================================
# Tool-Level Integration Tests
# =============================================================================


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear settings cache so env var changes take effect."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestScriptToolSafetyStrict:
    """Test that dangerous scripts are blocked in strict mode (default)."""

    @pytest.mark.asyncio
    async def test_create_script_blocked(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import create_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await create_script(
                adom="root",
                name="dangerous",
                content="execute factory-reset",
            )

        assert "error" in result
        assert "dangerous commands" in result["error"]
        # Client should NOT have been called
        mock_client.return_value.create_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_script_content_blocked(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import update_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await update_script(
                adom="root",
                name="existing-script",
                content="exec reboot",
            )

        assert "error" in result
        assert "dangerous commands" in result["error"]

    @pytest.mark.asyncio
    async def test_update_script_no_content_passes(self, monkeypatch):
        """Updating only description should not trigger safety check."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import update_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.update_script = AsyncMock(return_value={})
            result = await update_script(
                adom="root",
                name="existing-script",
                description="updated description",
            )

        assert "error" not in result
        assert result.get("success") is True


class TestScriptToolSafetyDisabled:
    """Test that dangerous scripts pass through when safety is disabled."""

    @pytest.mark.asyncio
    async def test_create_script_allowed(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "disabled")

        from fortimanager_mcp.tools.script_tools import create_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_script = AsyncMock(return_value={})
            result = await create_script(
                adom="root",
                name="dangerous",
                content="execute factory-reset",
            )

        assert result.get("success") is True
        mock_client.return_value.create_script.assert_called_once()
