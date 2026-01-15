#!/usr/bin/env python3
"""Integration tests against real FortiManager.

Run with: python tests/integration/test_real_fmg.py
Or: pytest tests/integration/test_real_fmg.py -v

Requires .env file with valid FMG credentials.
Only tests READ-ONLY operations - safe to run against production.
"""

import os
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path

# Suppress SSL warnings
warnings.filterwarnings("ignore")

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()


@dataclass
class TestResult:
    """Result of a single test."""

    module: str
    test: str
    passed: bool
    message: str
    data: dict | None = None


class FMGIntegrationTester:
    """Integration tester for FortiManager MCP tools."""

    def __init__(self):
        self.results: list[TestResult] = []
        self.client = None
        self.adom = "root"  # Default ADOM for testing

    def connect(self) -> bool:
        """Establish connection to FortiManager."""
        from pyFMG.fortimgr import FortiManager

        host = os.getenv("FORTIMANAGER_HOST", "").replace("https://", "").rstrip("/")
        api_token = os.getenv("FORTIMANAGER_API_TOKEN")
        username = os.getenv("FORTIMANAGER_USERNAME")
        password = os.getenv("FORTIMANAGER_PASSWORD")

        if not host:
            print("ERROR: FORTIMANAGER_HOST not set in .env")
            return False

        try:
            if api_token:
                self.fmg = FortiManager(
                    host,
                    apikey=api_token,
                    verify_ssl=False,
                    debug=False,
                    disable_request_warnings=True,
                )
            elif username and password:
                self.fmg = FortiManager(
                    host,
                    username,
                    password,
                    verify_ssl=False,
                    debug=False,
                    disable_request_warnings=True,
                )
            else:
                print("ERROR: No authentication configured")
                return False

            code, response = self.fmg.login()
            if code != 0:
                print(f"Login failed: {response}")
                return False

            print(f"Connected to {host}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from FortiManager."""
        if self.fmg:
            try:
                self.fmg.logout()
            except Exception:
                pass

    def add_result(
        self,
        module: str,
        test: str,
        passed: bool,
        message: str,
        data: dict | None = None,
    ):
        """Record a test result."""
        self.results.append(TestResult(module, test, passed, message, data))
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {test}: {message}")

    # =========================================================================
    # System Tools Tests
    # =========================================================================

    def test_system_tools(self):
        """Test system_tools module."""
        print("\n=== System Tools ===")

        # Test get_system_status
        try:
            status, response = self.fmg.get("/sys/status")
            if status == 0 and response:
                self.add_result(
                    "system_tools",
                    "get_system_status",
                    True,
                    f"Version: {response.get('Version', 'N/A')}",
                    response,
                )
            else:
                self.add_result("system_tools", "get_system_status", False, str(response))
        except Exception as e:
            self.add_result("system_tools", "get_system_status", False, str(e))

        # Test list_adoms
        try:
            status, response = self.fmg.get("/dvmdb/adom")
            if status == 0 and isinstance(response, list):
                adom_names = [a.get("name") for a in response[:5]]
                self.add_result(
                    "system_tools",
                    "list_adoms",
                    True,
                    f"Found {len(response)} ADOMs: {adom_names}...",
                )
                # Find a valid FortiGate ADOM for further tests
                # Prefer root, rootp, or custom ADOMs over product-specific ones
                skip_adoms = {
                    "FortiAnalyzer", "FortiAuthenticator", "FortiCache",
                    "FortiCarrier", "FortiClient", "FortiDDoS", "FortiDeceptor",
                    "FortiFirewall", "FortiFirewallCarrier", "FortiMail",
                    "FortiManager", "FortiProxy", "FortiSandbox", "FortiWeb",
                    "Syslog", "Unmanaged_Devices", "others"
                }
                for adom in response:
                    name = adom.get("name", "")
                    if name not in skip_adoms:
                        self.adom = name
                        print(f"  Using ADOM: {self.adom}")
                        break
            else:
                self.add_result("system_tools", "list_adoms", False, str(response))
        except Exception as e:
            self.add_result("system_tools", "list_adoms", False, str(e))

        # Test get_adom_details
        try:
            status, response = self.fmg.get(f"/dvmdb/adom/{self.adom}")
            if status == 0:
                self.add_result(
                    "system_tools",
                    "get_adom_details",
                    True,
                    f"ADOM '{self.adom}' state: {response.get('state', 'N/A')}",
                )
            else:
                self.add_result("system_tools", "get_adom_details", False, str(response))
        except Exception as e:
            self.add_result("system_tools", "get_adom_details", False, str(e))

        # Test list_tasks
        try:
            status, response = self.fmg.get("/task/task")
            if status == 0:
                count = len(response) if isinstance(response, list) else 0
                self.add_result("system_tools", "list_tasks", True, f"Found {count} tasks")
            else:
                self.add_result("system_tools", "list_tasks", False, str(response))
        except Exception as e:
            self.add_result("system_tools", "list_tasks", False, str(e))

    # =========================================================================
    # DVM Tools Tests (Device Management)
    # =========================================================================

    def test_dvm_tools(self):
        """Test dvm_tools module."""
        print("\n=== DVM Tools (Device Management) ===")

        # Test list_devices
        try:
            status, response = self.fmg.get(f"/dvmdb/adom/{self.adom}/device")
            if status == 0:
                devices = response if isinstance(response, list) else []
                device_names = [d.get("name") for d in devices[:5]]
                self.add_result(
                    "dvm_tools",
                    "list_devices",
                    True,
                    f"Found {len(devices)} devices: {device_names}",
                )
            else:
                self.add_result("dvm_tools", "list_devices", False, str(response))
        except Exception as e:
            self.add_result("dvm_tools", "list_devices", False, str(e))

        # Test get_device_groups
        try:
            status, response = self.fmg.get(f"/dvmdb/adom/{self.adom}/group")
            if status == 0:
                groups = response if isinstance(response, list) else []
                self.add_result(
                    "dvm_tools", "list_device_groups", True, f"Found {len(groups)} groups"
                )
            else:
                self.add_result("dvm_tools", "list_device_groups", False, str(response))
        except Exception as e:
            self.add_result("dvm_tools", "list_device_groups", False, str(e))

        # Test list_unregistered_devices
        try:
            status, response = self.fmg.get("/dvmdb/device", filter=["mgmt_mode", "==", 0])
            if status == 0:
                devices = response if isinstance(response, list) else []
                self.add_result(
                    "dvm_tools",
                    "list_unregistered_devices",
                    True,
                    f"Found {len(devices)} unregistered",
                )
            else:
                self.add_result("dvm_tools", "list_unregistered_devices", False, str(response))
        except Exception as e:
            self.add_result("dvm_tools", "list_unregistered_devices", False, str(e))

    # =========================================================================
    # Policy Tools Tests
    # =========================================================================

    def test_policy_tools(self):
        """Test policy_tools module."""
        print("\n=== Policy Tools ===")

        # Test list_policy_packages
        try:
            status, response = self.fmg.get(f"/pm/pkg/adom/{self.adom}")
            if status == 0:
                packages = response if isinstance(response, list) else []
                pkg_names = [p.get("name") for p in packages[:5]]
                self.add_result(
                    "policy_tools",
                    "list_policy_packages",
                    True,
                    f"Found {len(packages)} packages: {pkg_names}",
                )
                # Store first package for policy tests
                self._test_package = packages[0].get("name") if packages else None
            else:
                self.add_result("policy_tools", "list_policy_packages", False, str(response))
        except Exception as e:
            self.add_result("policy_tools", "list_policy_packages", False, str(e))

        # Test list_policies (if we have a package)
        if hasattr(self, "_test_package") and self._test_package:
            try:
                # Correct path for policy package policies
                status, response = self.fmg.get(
                    f"/pm/config/adom/{self.adom}/pkg/{self._test_package}/firewall/policy"
                )
                if status == 0:
                    policies = response if isinstance(response, list) else []
                    self.add_result(
                        "policy_tools",
                        "list_policies",
                        True,
                        f"Found {len(policies)} policies in '{self._test_package}'",
                    )
                elif status == -3:  # No policies yet
                    self.add_result(
                        "policy_tools",
                        "list_policies",
                        True,
                        f"No policies in '{self._test_package}' (empty package)",
                    )
                else:
                    self.add_result("policy_tools", "list_policies", False, str(response))
            except Exception as e:
                self.add_result("policy_tools", "list_policies", False, str(e))

        # Test get_installation_targets
        try:
            status, response = self.fmg.get(
                f"/pm/pkg/adom/{self.adom}"
            )
            if status == 0 and isinstance(response, list):
                # Check scope members in packages
                targets = []
                for pkg in response:
                    scope = pkg.get("scope member", [])
                    targets.extend([s.get("name") for s in scope if s.get("name")])
                self.add_result(
                    "policy_tools",
                    "get_installation_targets",
                    True,
                    f"Found {len(targets)} installation targets",
                )
            else:
                self.add_result("policy_tools", "get_installation_targets", False, str(response))
        except Exception as e:
            self.add_result("policy_tools", "get_installation_targets", False, str(e))

    # =========================================================================
    # Object Tools Tests
    # =========================================================================

    def test_object_tools(self):
        """Test object_tools module."""
        print("\n=== Object Tools ===")

        # Test list_addresses
        try:
            status, response = self.fmg.get(f"/pm/config/adom/{self.adom}/obj/firewall/address")
            if status == 0:
                addresses = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools",
                    "list_addresses",
                    True,
                    f"Found {len(addresses)} addresses",
                )
            else:
                self.add_result("object_tools", "list_addresses", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_addresses", False, str(e))

        # Test list_address_groups
        try:
            status, response = self.fmg.get(
                f"/pm/config/adom/{self.adom}/obj/firewall/addrgrp"
            )
            if status == 0:
                groups = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools",
                    "list_address_groups",
                    True,
                    f"Found {len(groups)} address groups",
                )
            else:
                self.add_result("object_tools", "list_address_groups", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_address_groups", False, str(e))

        # Test list_services
        try:
            status, response = self.fmg.get(
                f"/pm/config/adom/{self.adom}/obj/firewall/service/custom"
            )
            if status == 0:
                services = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools",
                    "list_services",
                    True,
                    f"Found {len(services)} custom services",
                )
            else:
                self.add_result("object_tools", "list_services", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_services", False, str(e))

        # Test list_service_groups
        try:
            status, response = self.fmg.get(
                f"/pm/config/adom/{self.adom}/obj/firewall/service/group"
            )
            if status == 0:
                groups = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools",
                    "list_service_groups",
                    True,
                    f"Found {len(groups)} service groups",
                )
            else:
                self.add_result("object_tools", "list_service_groups", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_service_groups", False, str(e))

        # Test list_vips
        try:
            status, response = self.fmg.get(f"/pm/config/adom/{self.adom}/obj/firewall/vip")
            if status == 0:
                vips = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools", "list_vips", True, f"Found {len(vips)} VIPs"
                )
            else:
                self.add_result("object_tools", "list_vips", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_vips", False, str(e))

        # Test list_ip_pools
        try:
            status, response = self.fmg.get(f"/pm/config/adom/{self.adom}/obj/firewall/ippool")
            if status == 0:
                pools = response if isinstance(response, list) else []
                self.add_result(
                    "object_tools", "list_ip_pools", True, f"Found {len(pools)} IP pools"
                )
            else:
                self.add_result("object_tools", "list_ip_pools", False, str(response))
        except Exception as e:
            self.add_result("object_tools", "list_ip_pools", False, str(e))

    # =========================================================================
    # Script Tools Tests
    # =========================================================================

    def test_script_tools(self):
        """Test script_tools module."""
        print("\n=== Script Tools ===")

        # Test list_scripts
        try:
            status, response = self.fmg.get(f"/dvmdb/adom/{self.adom}/script")
            if status == 0:
                scripts = response if isinstance(response, list) else []
                script_names = [s.get("name") for s in scripts[:5]]
                self.add_result(
                    "script_tools",
                    "list_scripts",
                    True,
                    f"Found {len(scripts)} scripts: {script_names}",
                )
            else:
                self.add_result("script_tools", "list_scripts", False, str(response))
        except Exception as e:
            self.add_result("script_tools", "list_scripts", False, str(e))

        # Test list_script_logs
        try:
            status, response = self.fmg.get(f"/dvmdb/adom/{self.adom}/script/log/summary")
            if status == 0:
                logs = response if isinstance(response, list) else []
                self.add_result(
                    "script_tools", "list_script_logs", True, f"Found {len(logs)} script logs"
                )
            else:
                # Script logs might not exist
                self.add_result(
                    "script_tools",
                    "list_script_logs",
                    status == -3,  # No data is acceptable
                    f"Status: {status}",
                )
        except Exception as e:
            self.add_result("script_tools", "list_script_logs", False, str(e))

    # =========================================================================
    # SD-WAN Tools Tests
    # =========================================================================

    def test_sdwan_tools(self):
        """Test sdwan_tools module."""
        print("\n=== SD-WAN Tools ===")

        # Test list_sdwan_templates
        try:
            status, response = self.fmg.get(f"/pm/wanprof/adom/{self.adom}")
            if status == 0:
                templates = response if isinstance(response, list) else []
                self.add_result(
                    "sdwan_tools",
                    "list_sdwan_templates",
                    True,
                    f"Found {len(templates)} SD-WAN templates",
                )
            else:
                self.add_result("sdwan_tools", "list_sdwan_templates", False, str(response))
        except Exception as e:
            self.add_result("sdwan_tools", "list_sdwan_templates", False, str(e))

    # =========================================================================
    # Template Tools Tests
    # =========================================================================

    def test_template_tools(self):
        """Test template_tools module."""
        print("\n=== Template Tools ===")

        # Test list_cli_templates
        try:
            status, response = self.fmg.get(f"/pm/config/adom/{self.adom}/obj/cli/template")
            if status == 0:
                templates = response if isinstance(response, list) else []
                self.add_result(
                    "template_tools",
                    "list_cli_templates",
                    True,
                    f"Found {len(templates)} CLI templates",
                )
            else:
                self.add_result("template_tools", "list_cli_templates", False, str(response))
        except Exception as e:
            self.add_result("template_tools", "list_cli_templates", False, str(e))

        # Test list_cli_template_groups
        try:
            status, response = self.fmg.get(
                f"/pm/config/adom/{self.adom}/obj/cli/template-group"
            )
            if status == 0:
                groups = response if isinstance(response, list) else []
                self.add_result(
                    "template_tools",
                    "list_cli_template_groups",
                    True,
                    f"Found {len(groups)} CLI template groups",
                )
            else:
                self.add_result("template_tools", "list_cli_template_groups", False, str(response))
        except Exception as e:
            self.add_result("template_tools", "list_cli_template_groups", False, str(e))

        # Test list_system_templates
        try:
            status, response = self.fmg.get(f"/pm/devprof/adom/{self.adom}")
            if status == 0:
                templates = response if isinstance(response, list) else []
                self.add_result(
                    "template_tools",
                    "list_system_templates",
                    True,
                    f"Found {len(templates)} system templates",
                )
            else:
                self.add_result("template_tools", "list_system_templates", False, str(response))
        except Exception as e:
            self.add_result("template_tools", "list_system_templates", False, str(e))

    # =========================================================================
    # Run All Tests
    # =========================================================================

    def run_all(self) -> bool:
        """Run all integration tests."""
        print("=" * 60)
        print("FortiManager MCP Integration Tests")
        print("=" * 60)

        if not self.connect():
            return False

        try:
            self.test_system_tools()
            self.test_dvm_tools()
            self.test_policy_tools()
            self.test_object_tools()
            self.test_script_tools()
            self.test_sdwan_tools()
            self.test_template_tools()
        finally:
            self.disconnect()

        # Print summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        # Group by module
        modules = {}
        for r in self.results:
            if r.module not in modules:
                modules[r.module] = {"passed": 0, "failed": 0}
            if r.passed:
                modules[r.module]["passed"] += 1
            else:
                modules[r.module]["failed"] += 1

        print(f"\n{'Module':<20} {'Passed':<10} {'Failed':<10}")
        print("-" * 40)
        for module, counts in modules.items():
            print(f"{module:<20} {counts['passed']:<10} {counts['failed']:<10}")
        print("-" * 40)
        print(f"{'TOTAL':<20} {passed:<10} {failed:<10}")

        print(f"\nResult: {passed}/{total} tests passed")

        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.module}/{r.test}: {r.message}")

        return failed == 0


def main():
    """Run integration tests."""
    tester = FMGIntegrationTester()
    success = tester.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
