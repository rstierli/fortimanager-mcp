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

    # --- Broadened high-impact config changes ---

    def test_blocks_config_system_admin(self):
        content = "config system admin\nedit backdoor\nset password x\nend"
        matches = validate_script_content(content)
        assert "config-system-admin" in matches

    def test_blocks_set_action_accept(self):
        content = "config firewall policy\nedit 0\nset action accept\nend"
        assert "set-action-accept" in validate_script_content(content)

    def test_blocks_set_status_disable(self):
        content = "config log syslogd setting\nset status disable\nend"
        assert "set-status-disable" in validate_script_content(content)

    def test_blocks_config_system_dns(self):
        content = "config system dns\nset primary 8.8.8.8\nend"
        assert "config-system-dns" in validate_script_content(content)

    def test_blocks_config_router_static(self):
        content = "config router static\nedit 1\nset gateway 1.2.3.4\nend"
        assert "config-router-static" in validate_script_content(content)

    def test_normalizes_whitespace_cannot_bypass(self):
        """Extra spaces/tabs/newlines between tokens must not bypass the check."""
        assert "config-system-admin" in validate_script_content("config   system\tadmin")
        assert "config-system-admin" in validate_script_content("config\n system\n admin")

    def test_safe_dns_in_comment_still_safe(self):
        """A plain config that doesn't hit a dangerous block stays safe."""
        assert validate_script_content("config system interface\nset role lan\nend") == []

    # --- FortiOS command-prefix abbreviations must not bypass the check ---

    def test_blocks_abbreviated_exe_reboot(self):
        matches = validate_script_content("exe reboot")
        assert "reboot" in matches

    def test_blocks_abbreviated_execu_factory_reset(self):
        matches = validate_script_content("execu factory-reset")
        assert "factory-reset" in matches

    def test_blocks_abbreviated_conf_sys_admin(self):
        matches = validate_script_content("conf sys admin\nedit backdoor\nend")
        assert "config-system-admin" in matches

    def test_blocks_abbreviated_conf_syst_dns(self):
        matches = validate_script_content("conf syst dns\nset primary 8.8.8.8\nend")
        assert "config-system-dns" in matches

    def test_blocks_abbreviated_conf_rout_static(self):
        matches = validate_script_content("conf rout static\nedit 1\nend")
        assert "config-router-static" in matches

    def test_plain_safe_content_still_passes(self):
        """Broadened abbreviation patterns must not flag ordinary safe scripts."""
        content = "config system interface\nedit port1\nset ip 10.0.0.1/24\nend"
        assert validate_script_content(content) == []
        assert validate_script_content("execute ping 8.8.8.8") == []


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


class TestExecutePathReValidation:
    """Execute tools must re-check the stored script body before running it."""

    @pytest.mark.asyncio
    async def test_execute_blocked_when_stored_script_dangerous(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        # Stored script (created while safety was off / pre-existing) is dangerous
        client.get_script = AsyncMock(return_value={"content": "execute reboot"})
        client.execute_script = AsyncMock(return_value={"task": 1})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_device(adom="root", script="evil", device="FGT-01")

        assert "error" in result
        assert "dangerous commands" in result["error"]
        client.execute_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_allowed_when_stored_script_safe(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        client.get_script = AsyncMock(return_value={"content": "config system interface\nend"})
        client.execute_script = AsyncMock(return_value={"task": 42})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_device(adom="root", script="safe", device="FGT-01")

        assert result.get("success") is True
        client.execute_script.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_fail_closed_when_script_unresolvable(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import execute_script_on_package

        client = AsyncMock()
        client.get_script = AsyncMock(side_effect=Exception("not found"))
        client.execute_script = AsyncMock(return_value={"task": 1})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_package(adom="root", script="ghost", package="default")

        assert "error" in result
        client.execute_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_allowed_when_safety_disabled(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "disabled")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        client.get_script = AsyncMock(return_value={"content": "execute reboot"})
        client.execute_script = AsyncMock(return_value={"task": 7})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_device(adom="root", script="evil", device="FGT-01")

        assert result.get("success") is True
        client.execute_script.assert_called_once()
        # When safety is disabled we must NOT pre-fetch the script body
        client.get_script.assert_not_called()


class TestExecutePathInputValidation:
    """Execute tools must reject malformed identifiers before any API call."""

    @pytest.mark.asyncio
    async def test_rejects_bad_device_name(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        client.get_script = AsyncMock(return_value={"content": "config x\nend"})
        client.execute_script = AsyncMock(return_value={"task": 1})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            # Path-injection style device name
            result = await execute_script_on_device(
                adom="root", script="safe", device="../../etc/passwd"
            )

        assert "error" in result
        client.get_script.assert_not_called()
        client.execute_script.assert_not_called()


class TestScriptTypeSafety:
    """Tcl scripts assemble commands at runtime, defeating static screening.

    Under strict safety they must be blocked at create/update/execute time, and
    allowed only when safety is explicitly disabled.
    """

    @pytest.mark.asyncio
    async def test_create_tcl_blocked_strict(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import create_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await create_script(
                adom="root",
                name="tcljob",
                content="puts hello",
                script_type="tcl",
            )

        assert "error" in result
        assert "tcl" in result["error"].lower()
        mock_client.return_value.create_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_tclgrp_blocked_strict(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import update_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await update_script(
                adom="root",
                name="existing-script",
                script_type="tclgrp",
            )

        assert "error" in result
        assert "tclgrp" in result["error"].lower()
        mock_client.return_value.update_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_tcl_blocked_strict(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "strict")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        # Content looks benign, but the stored type is Tcl (runtime-assembled)
        client.get_script = AsyncMock(return_value={"content": "puts hi", "type": "tcl"})
        client.execute_script = AsyncMock(return_value={"task": 1})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_device(adom="root", script="tcljob", device="FGT-01")

        assert "error" in result
        assert "tcl" in result["error"].lower()
        client.execute_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_tcl_allowed_when_disabled(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "disabled")

        from fortimanager_mcp.tools.script_tools import create_script

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_script = AsyncMock(return_value={})
            result = await create_script(
                adom="root",
                name="tcljob",
                content="puts hello",
                script_type="tcl",
            )

        assert result.get("success") is True
        mock_client.return_value.create_script.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_tcl_allowed_when_disabled(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_SCRIPT_SAFETY", "disabled")

        from fortimanager_mcp.tools.script_tools import execute_script_on_device

        client = AsyncMock()
        client.get_script = AsyncMock(return_value={"content": "puts hi", "type": "tcl"})
        client.execute_script = AsyncMock(return_value={"task": 5})

        with patch("fortimanager_mcp.tools.script_tools.get_fmg_client", return_value=client):
            result = await execute_script_on_device(adom="root", script="tcljob", device="FGT-01")

        assert result.get("success") is True
        client.execute_script.assert_called_once()
        # Safety disabled → no pre-fetch of the stored script body
        client.get_script.assert_not_called()
