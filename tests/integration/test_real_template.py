"""Integration tests for template operations against real FortiManager.

Tests:
- List available templates
- Create simple CLI template group
- Validate template (if device available)
- Cleanup
"""

import pytest

from fortimanager_mcp.api.client import FortiManagerClient


pytestmark = pytest.mark.integration


class TestTemplateOperations:
    """Test template-related operations."""

    @pytest.mark.asyncio
    async def test_list_templates(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing provisioning templates."""
        templates = await fmg_client.list_templates(test_adom)

        assert isinstance(templates, list)
        # Templates might be empty if none configured

    @pytest.mark.asyncio
    async def test_list_system_templates(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing system templates (devprof)."""
        templates = await fmg_client.list_system_templates(test_adom)

        assert isinstance(templates, list)

    @pytest.mark.asyncio
    async def test_list_template_groups(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing template groups."""
        groups = await fmg_client.list_template_groups(test_adom)

        assert isinstance(groups, list)

    @pytest.mark.asyncio
    async def test_list_cli_template_groups(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing CLI template groups."""
        groups = await fmg_client.list_cli_template_groups(test_adom)

        assert isinstance(groups, list)


class TestCLITemplateGroupLifecycle:
    """Test CLI template group create/delete lifecycle."""

    @pytest.mark.asyncio
    async def test_01_create_cli_template_group(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_cli_template_group_name: str,
    ):
        """Create a CLI template group."""
        # Clean up if exists from previous run
        try:
            await fmg_client.delete_cli_template_group(
                test_adom, test_cli_template_group_name
            )
        except Exception:
            pass

        group = {
            "name": test_cli_template_group_name,
            "description": "MCP integration test CLI template group - safe to delete",
        }

        result = await fmg_client.create_cli_template_group(test_adom, group)
        assert result is not None

        # Verify it exists
        groups = await fmg_client.list_cli_template_groups(test_adom)
        group_names = [g.get("name") for g in groups]
        assert test_cli_template_group_name in group_names

    @pytest.mark.asyncio
    async def test_02_get_cli_template_group(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_cli_template_group_name: str,
    ):
        """Get the created CLI template group."""
        group = await fmg_client.get_cli_template_group(
            test_adom, test_cli_template_group_name
        )

        assert group is not None
        assert group.get("name") == test_cli_template_group_name

    @pytest.mark.asyncio
    async def test_90_cleanup_cli_template_group(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_cli_template_group_name: str,
    ):
        """Cleanup: delete the CLI template group."""
        try:
            result = await fmg_client.delete_cli_template_group(
                test_adom, test_cli_template_group_name
            )
            assert result is not None
        except Exception:
            pass  # Might already be deleted

        # Verify it's gone
        groups = await fmg_client.list_cli_template_groups(test_adom)
        group_names = [g.get("name") for g in groups]
        assert test_cli_template_group_name not in group_names


class TestScriptOperations:
    """Test CLI script operations."""

    @pytest.mark.asyncio
    async def test_list_scripts(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing CLI scripts."""
        scripts = await fmg_client.list_scripts(test_adom)

        assert isinstance(scripts, list)


class TestScriptLifecycle:
    """Test CLI script create/delete lifecycle."""

    @pytest.mark.asyncio
    async def test_01_create_script(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_script_name: str,
    ):
        """Create a test CLI script."""
        # Clean up if exists
        try:
            await fmg_client.delete_script(test_adom, test_script_name)
        except Exception:
            pass

        script = {
            "name": test_script_name,
            "type": "cli",
            "target": "device_database",
            "content": "# MCP integration test script\nconfig system global\nend",
            "desc": "MCP integration test script - safe to delete",
        }

        result = await fmg_client.create_script(test_adom, script)
        assert result is not None

        # Verify it exists
        scripts = await fmg_client.list_scripts(test_adom)
        script_names = [s.get("name") for s in scripts]
        assert test_script_name in script_names

    @pytest.mark.asyncio
    async def test_02_get_script(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_script_name: str,
    ):
        """Get the created script."""
        script = await fmg_client.get_script(test_adom, test_script_name)

        assert script is not None
        assert script.get("name") == test_script_name
        assert "content" in script

    @pytest.mark.asyncio
    async def test_03_update_script(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_script_name: str,
    ):
        """Update the script content."""
        update_data = {
            "content": "# MCP integration test script - UPDATED\nconfig system global\nend",
            "desc": "Updated description",
        }

        result = await fmg_client.update_script(
            test_adom, test_script_name, update_data
        )
        assert result is not None

        # Verify update
        script = await fmg_client.get_script(test_adom, test_script_name)
        assert "UPDATED" in script.get("content", "")

    @pytest.mark.asyncio
    async def test_90_cleanup_script(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_script_name: str,
    ):
        """Cleanup: delete the test script."""
        try:
            result = await fmg_client.delete_script(test_adom, test_script_name)
            assert result is not None
        except Exception:
            pass

        # Verify it's gone
        scripts = await fmg_client.list_scripts(test_adom)
        script_names = [s.get("name") for s in scripts]
        assert test_script_name not in script_names


class TestSDWanTemplates:
    """Test SD-WAN template operations."""

    @pytest.mark.asyncio
    async def test_list_sdwan_templates(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing SD-WAN templates."""
        templates = await fmg_client.list_sdwan_templates(test_adom)

        assert isinstance(templates, list)
        # SD-WAN templates might be empty if none configured
