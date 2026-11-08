"""MCP prompts: the bundled skills, served to any MCP client.

A skill reaches Claude Code only when it is linked into a skills folder, so each
one is also exposed as a prompt that ships with the server. ``SKILL.md`` under
``skills/`` stays the single source of both. Prompts cost nothing until a client
requests one, and they load in full and dynamic tool mode alike.
"""

from pathlib import Path

from fortimanager_mcp.server import mcp

_SKILLS_DIR = Path(__file__).parent / "skills"


def _skill_body(name: str) -> str:
    """Read a bundled skill, without its YAML frontmatter."""
    text = (_SKILLS_DIR / name / "SKILL.md").read_text(encoding="utf-8")
    if text.startswith("---\n"):
        text = text.split("\n---\n", 1)[1]
    return text.strip()


def _with_context(name: str, heading: str, context: str) -> str:
    """A skill body, followed by what the caller reported."""
    body = _skill_body(name)
    return f"{body}\n\n## {heading}\n{context}" if context else body


@mcp.prompt(
    name="troubleshoot_sdwan_overlay",
    description=(
        "Troubleshoot a SD-WAN overlay failure layer by layer: tunnels up but no "
        "traffic, BGP not coming up, failures after re-running the Overlay Template"
    ),
)
def troubleshoot_sdwan_overlay(symptom: str = "") -> str:
    """Return the overlay troubleshooting procedure, with the reported symptom."""
    return _with_context("fmg-sdwan-overlay-troubleshoot", "Reported symptom", symptom)


@mcp.prompt(
    name="audit_firewall_policy",
    description=(
        "Audit a policy package for shadowed, broad or leftover rules, "
        "or explain why one flow is allowed or blocked"
    ),
)
def audit_firewall_policy(target: str = "") -> str:
    """Return the firewall policy audit procedure, with the package or flow."""
    return _with_context("fmg-firewall-policy-audit", "Target", target)


@mcp.prompt(
    name="diagnose_install_status",
    description=(
        "Explain a conflict, out of sync or modified status, and whether installing is safe"
    ),
)
def diagnose_install_status(target: str = "") -> str:
    """Return the install status procedure, with the device or package."""
    return _with_context("fmg-install-status-diagnosis", "Target", target)


@mcp.prompt(
    name="diagnose_install_failure",
    description="Find why an install or install preview failed, from its task history",
)
def diagnose_install_failure(symptom: str = "") -> str:
    """Return the install failure procedure, with the reported error."""
    return _with_context("fmg-install-failure-diagnosis", "Reported error", symptom)


@mcp.prompt(
    name="check_template_rerun",
    description="Check what a re-run or edited SD-WAN Overlay Template changes, around an install",
)
def check_template_rerun(context: str = "") -> str:
    """Return the template re-run checks, with what was changed."""
    return _with_context("fmg-template-rerun-check", "What changed", context)


@mcp.prompt(
    name="trace_flow",
    description=(
        "Trace a flow between two IPs across FortiGates, with rules, tunnels and logs. "
        "Works best with the fortianalyzer MCP server connected too"
    ),
)
def trace_flow(source: str = "", destination: str = "") -> str:
    """Return the flow trace procedure, with the flow to trace."""
    flow = f"{source} -> {destination}" if source and destination else ""
    return _with_context("fmg-faz-flow-trace", "Flow", flow)


@mcp.prompt(
    name="locate_host",
    description="Find the FortiSwitch port, VLAN or FortiAP of a host from its IP, MAC or hostname",
)
def locate_host(host: str = "") -> str:
    """Return the host location procedure, with the host to find."""
    return _with_context("fmg-host-location", "Host", host)


@mcp.prompt(
    name="check_device_health",
    description="Check why a FortiGate looks down or unmanaged, or review its general health",
)
def check_device_health(device: str = "") -> str:
    """Return the device health procedure, with the device concerned."""
    return _with_context("fmg-device-health", "Device", device)
