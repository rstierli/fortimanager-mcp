"""MCP prompts built from the bundled skills."""

import re
from pathlib import Path

import pytest

from fortimanager_mcp import prompts
from fortimanager_mcp.server import mcp

_SKILLS = sorted(Path(prompts.__file__).parent.joinpath("skills").glob("*/SKILL.md"))
_PROMPTS = {
    "troubleshoot_sdwan_overlay",
    "audit_firewall_policy",
    "diagnose_install_status",
    "diagnose_install_failure",
    "check_template_rerun",
    "check_device_health",
    "trace_flow",
    "locate_host",
}
_TOOL_REFERENCE = re.compile(
    r"`((?:get|list|check|preview|install|diff|diagnose|query|policy)_[a-z0-9_]+)(?:\(.*?\))?`"
)
#: Names that are not tools of this server: result fields of
#: check_device_policy_sync, and fortianalyzer tools.
_NOT_TOOLS = {
    "package_vs_revision",
    "package_vs_device_db",
    "device_db_vs_revision",
    # Tools of the fortianalyzer MCP server.
    "query_logs",
    "get_log_stats",
}


class TestTroubleshootSdwanOverlay:
    def test_body_has_no_frontmatter(self) -> None:
        body = prompts.troubleshoot_sdwan_overlay()

        assert body.startswith("# SD-WAN overlay failure")
        assert "description:" not in body

    def test_symptom_is_appended(self) -> None:
        body = prompts.troubleshoot_sdwan_overlay("BGP stuck in Connect")
        assert body.endswith("## Reported symptom\nBGP stuck in Connect")

    @pytest.mark.asyncio
    async def test_is_served_by_the_server(self) -> None:
        listed = await mcp.list_prompts()
        assert "troubleshoot_sdwan_overlay" in [p.name for p in listed]


class TestAllSkills:
    @pytest.mark.asyncio
    async def test_every_skill_has_a_prompt(self) -> None:
        listed = {p.name for p in await mcp.list_prompts()}

        assert listed == _PROMPTS
        assert len(_SKILLS) == len(_PROMPTS)

    @pytest.mark.asyncio
    async def test_prompts_render(self) -> None:
        for name in _PROMPTS:
            result = await mcp.get_prompt(name, {})
            assert result.messages

    @pytest.mark.parametrize("skill", _SKILLS, ids=lambda p: p.parent.name)
    def test_frontmatter_name_matches_the_folder(self, skill: Path) -> None:
        assert f"name: {skill.parent.name}\n" in skill.read_text(encoding="utf-8")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("skill", _SKILLS, ids=lambda p: p.parent.name)
    async def test_referenced_tools_exist(self, skill: Path) -> None:
        tools = {t.name for t in await mcp.list_tools()}
        referenced = set(_TOOL_REFERENCE.findall(skill.read_text(encoding="utf-8")))

        assert not referenced - tools - _NOT_TOOLS


def test_flow_report_template_is_bundled() -> None:
    skill = next(p for p in _SKILLS if p.parent.name == "fmg-faz-flow-trace")
    template = skill.parent / "references" / "report-template.html"

    assert "{{HOPS_TABLE}}" in template.read_text(encoding="utf-8")
