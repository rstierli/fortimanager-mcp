"""FortiManager API client wrapper using pyfmg library.

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import json
import logging
from typing import Any

from pyFMG.fortimgr import FortiManager

from fortimanager_mcp.utils.config import Settings
from fortimanager_mcp.utils.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
)

logger = logging.getLogger(__name__)


def _sanitize_for_logging(data: Any, depth: int = 0) -> Any:
    """Sanitize sensitive data before logging."""
    SENSITIVE_FIELDS = {
        "password", "passwd", "pass", "adm_pass", "api_token",
        "apikey", "token", "session", "sid", "authorization", "secret",
    }
    MASK = "***REDACTED***"

    if depth > 10:
        return "<MAX_DEPTH>"

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_")
            if any(s in key_lower for s in SENSITIVE_FIELDS):
                result[key] = MASK
            else:
                result[key] = _sanitize_for_logging(value, depth + 1)
        return result
    elif isinstance(data, list):
        return [_sanitize_for_logging(item, depth + 1) for item in data]
    return data


def parse_fmg_error(code: int, message: str, operation: str = "") -> APIError:
    """Parse FortiManager error code and return appropriate exception."""
    error_map = {
        -1: "General error",
        -2: "Invalid parameters",
        -3: "Object not found",
        -6: "Object already exists",
        -10: "Invalid session",
        -11: "No permission",
    }
    base_msg = error_map.get(code, f"Unknown error (code {code})")
    full_msg = f"{operation}: {base_msg} - {message}" if operation else f"{base_msg} - {message}"
    return APIError(full_msg)


class FortiManagerClient:
    """Client for FortiManager JSON RPC API using pyfmg library.

    This client wraps the pyfmg FortiManager class for accessing
    FortiManager's JSON-RPC API.

    Based on FNDN FortiManager 7.6.5 specifications.
    """

    def __init__(
        self,
        host: str,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize FortiManager client."""
        self.host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self.api_token = api_token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries

        self._fmg: FortiManager | None = None
        self._connected = False

        logger.info(f"Initialized FortiManager client for {self.host}")

    @classmethod
    def from_settings(cls, settings: Settings) -> "FortiManagerClient":
        """Create client from settings."""
        return cls(
            host=settings.fortimanager_host,
            api_token=settings.fortimanager_api_token or None,
            username=settings.fortimanager_username or None,
            password=settings.fortimanager_password or None,
            verify_ssl=settings.fortimanager_verify_ssl,
            timeout=settings.fortimanager_timeout,
            max_retries=settings.fortimanager_max_retries,
        )

    async def connect(self) -> None:
        """Establish connection and authenticate."""
        if self._connected:
            logger.warning("Client already connected")
            return

        logger.info("Connecting to FortiManager")

        try:
            if self.api_token:
                self._fmg = FortiManager(
                    self.host,
                    apikey=self.api_token,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                )
            elif self.username and self.password:
                self._fmg = FortiManager(
                    self.host,
                    self.username,
                    self.password,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                )
            else:
                raise AuthenticationError(
                    "No authentication provided. Set API token or username/password."
                )

            code, response = self._fmg.login()

            if code != 0:
                error_msg = response.get("status", {}).get("message", "Login failed")
                raise AuthenticationError(f"FortiManager login failed: {error_msg}")

            self._connected = True
            logger.info("Successfully connected to FortiManager")

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect to FortiManager: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect and cleanup resources."""
        if not self._connected or not self._fmg:
            return

        logger.info("Disconnecting from FortiManager")

        try:
            self._fmg.logout()
        except Exception as e:
            logger.warning(f"Logout failed: {e}")
        finally:
            self._fmg = None
            self._connected = False
            logger.info("Disconnected from FortiManager")

    async def __aenter__(self) -> "FortiManagerClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._fmg is not None

    def _ensure_connected(self) -> FortiManager:
        """Ensure client is connected and return pyfmg instance."""
        if not self._connected or not self._fmg:
            raise ConnectionError("Not connected. Call connect() first.")
        return self._fmg

    def _handle_response(self, code: int, response: Any, operation: str = "operation") -> Any:
        """Handle pyfmg response and raise appropriate exceptions."""
        if code == 0:
            return response

        if isinstance(response, dict):
            error_msg = response.get("status", {}).get("message", str(response))
        else:
            error_msg = str(response)

        raise parse_fmg_error(code, error_msg, operation)

    # =========================================================================
    # Generic Operations
    # =========================================================================

    async def get(self, url: str, **kwargs: Any) -> Any:
        """Execute GET request."""
        fmg = self._ensure_connected()
        code, response = fmg.get(url, **kwargs)
        return self._handle_response(code, response, f"GET {url}")

    async def add(self, url: str, **kwargs: Any) -> Any:
        """Execute ADD request."""
        fmg = self._ensure_connected()
        code, response = fmg.add(url, **kwargs)
        return self._handle_response(code, response, f"ADD {url}")

    async def set(self, url: str, **kwargs: Any) -> Any:
        """Execute SET request."""
        fmg = self._ensure_connected()
        code, response = fmg.set(url, **kwargs)
        return self._handle_response(code, response, f"SET {url}")

    async def update(self, url: str, **kwargs: Any) -> Any:
        """Execute UPDATE request."""
        fmg = self._ensure_connected()
        code, response = fmg.update(url, **kwargs)
        return self._handle_response(code, response, f"UPDATE {url}")

    async def delete(self, url: str, **kwargs: Any) -> Any:
        """Execute DELETE request."""
        fmg = self._ensure_connected()
        code, response = fmg.delete(url, **kwargs)
        return self._handle_response(code, response, f"DELETE {url}")

    async def execute(self, url: str, **kwargs: Any) -> Any:
        """Execute EXEC request."""
        fmg = self._ensure_connected()
        code, response = fmg.execute(url, **kwargs)
        return self._handle_response(code, response, f"EXEC {url}")

    # =========================================================================
    # System Status (from sys.json)
    # =========================================================================

    async def get_system_status(self) -> dict[str, Any]:
        """Get FortiManager system status.

        FNDN: GET /sys/status
        """
        return await self.get("/sys/status")

    async def get_ha_status(self) -> dict[str, Any]:
        """Get HA status.

        FNDN: GET /sys/ha/status
        """
        return await self.get("/sys/ha/status")

    # =========================================================================
    # DVMDB - Device Manager Database
    # =========================================================================

    async def list_adoms(
        self,
        fields: list[str] | None = None,
        filter: list[str] | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List all ADOMs.

        FNDN: GET /dvmdb/adom
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get("/dvmdb/adom", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_adom(self, name: str, loadsub: int = 0) -> dict[str, Any]:
        """Get specific ADOM.

        FNDN: GET /dvmdb/adom/{adom}
        """
        return await self.get(f"/dvmdb/adom/{name}", loadsub=loadsub)

    async def list_devices(
        self,
        adom: str = "root",
        fields: list[str] | None = None,
        filter: list[str] | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List devices in ADOM.

        FNDN: GET /dvmdb/adom/{adom}/device
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/dvmdb/adom/{adom}/device", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_device(
        self, device: str, adom: str = "root", loadsub: int = 0
    ) -> dict[str, Any]:
        """Get specific device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}
        """
        return await self.get(f"/dvmdb/adom/{adom}/device/{device}", loadsub=loadsub)

    async def list_device_vdoms(
        self, device: str, adom: str = "root"
    ) -> list[dict[str, Any]]:
        """List VDOMs for a device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}/vdom
        """
        result = await self.get(f"/dvmdb/adom/{adom}/device/{device}/vdom")
        return result if isinstance(result, list) else [result] if result else []

    async def list_device_groups(self, adom: str = "root") -> list[dict[str, Any]]:
        """List device groups.

        FNDN: GET /dvmdb/adom/{adom}/group
        """
        result = await self.get(f"/dvmdb/adom/{adom}/group")
        return result if isinstance(result, list) else [result] if result else []

    # =========================================================================
    # DVM Commands (Device Virtual Manager)
    # =========================================================================

    async def add_device(
        self,
        adom: str,
        device: dict[str, Any],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a device to FortiManager.

        FNDN: EXEC /dvm/cmd/add/device

        Args:
            adom: ADOM name
            device: Device configuration dict with:
                - name: Device name (required)
                - ip: Device IP
                - adm_usr: Admin username
                - adm_pass: Admin password
                - sn: Serial number
                - mgmt_mode: Management mode (fmg, faz, fmgfaz)
                - device action: "add_model" for offline provisioning
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/device", **data)

    async def delete_device(
        self,
        adom: str,
        device: str,
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete a device from FortiManager.

        FNDN: EXEC /dvm/cmd/del/device
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/device", **data)

    async def reload_device_list(self, adom: str = "root") -> dict[str, Any]:
        """Reload device list.

        FNDN: EXEC /dvm/cmd/reload/dev-list
        """
        return await self.execute("/dvm/cmd/reload/dev-list", adom=adom)

    async def add_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add multiple devices.

        FNDN: EXEC /dvm/cmd/add/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "add-dev-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/dev-list", **data)

    async def delete_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete multiple devices.

        FNDN: EXEC /dvm/cmd/del/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "del-dev-member-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/dev-list", **data)

    async def update_device(
        self,
        adom: str,
        device: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update device properties.

        FNDN: UPDATE /dvmdb/adom/{adom}/device/{device}
        """
        return await self.update(f"/dvmdb/adom/{adom}/device/{device}", **data)

    async def get_device_status(
        self,
        adom: str = "root",
        device: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get device status (config sync, connection status).

        FNDN: GET /dvmdb/adom/{adom}/device with status fields
        """
        fields = [
            "name", "ip", "sn", "conn_status", "conf_status",
            "db_status", "dev_status", "os_ver", "platform_str",
        ]
        filter_param = [["name", "==", device]] if device else None
        return await self.list_devices(adom, fields=fields, filter=filter_param)

    # =========================================================================
    # Task Management
    # =========================================================================

    async def list_tasks(
        self,
        filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List all tasks.

        FNDN: GET /task/task
        """
        params: dict[str, Any] = {}
        if filter:
            params["filter"] = filter

        result = await self.get("/task/task", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_task(self, task_id: int) -> dict[str, Any]:
        """Get task details.

        FNDN: GET /task/task/{task_id}
        """
        return await self.get(f"/task/task/{task_id}")

    async def get_task_line(self, task_id: int) -> list[dict[str, Any]]:
        """Get task line details.

        FNDN: GET /task/task/{task_id}/line
        """
        result = await self.get(f"/task/task/{task_id}/line")
        return result if isinstance(result, list) else [result] if result else []

    # =========================================================================
    # Security Console - Installation Operations
    # =========================================================================

    async def install_package(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install a policy package to devices.

        FNDN: EXEC /securityconsole/install/package

        Args:
            adom: ADOM name
            pkg: Package name
            scope: Target devices [{"name": "FGT1", "vdom": "root"}, ...]
            flags: Install flags (e.g., ["none"], ["preview"])

        Returns:
            {"task": <task_id>} - Task ID for monitoring
        """
        data: dict[str, Any] = {
            "adom": adom,
            "pkg": pkg,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/package", **data)

    async def install_device(
        self,
        adom: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install device settings only (without policy package).

        FNDN: EXEC /securityconsole/install/device
        """
        data: dict[str, Any] = {
            "adom": adom,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/device", **data)

    async def install_preview(
        self,
        adom: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Preview installation before applying.

        FNDN: EXEC /securityconsole/install/preview

        Args:
            flags: Preview flags (e.g., ["json"] for JSON output)
        """
        data: dict[str, Any] = {
            "adom": adom,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/preview", **data)

    async def get_preview_result(
        self,
        adom: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Get preview result after install/preview completes.

        FNDN: EXEC /securityconsole/preview/result
        """
        return await self.execute(
            "/securityconsole/preview/result",
            adom=adom,
            scope=scope,
        )

    # =========================================================================
    # Policy Package Management
    # =========================================================================

    async def list_packages(
        self,
        adom: str = "root",
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List policy packages in ADOM.

        FNDN: GET /pm/pkg/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/pkg/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_package(
        self,
        adom: str,
        pkg: str,
        loadsub: int = 0,
    ) -> dict[str, Any]:
        """Get policy package details.

        FNDN: GET /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.get(f"/pm/pkg/adom/{adom}/{pkg}", loadsub=loadsub)

    async def create_package(
        self,
        adom: str,
        name: str,
        package_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new policy package.

        FNDN: ADD /pm/pkg/adom/{adom}
        """
        data: dict[str, Any] = {
            "name": name,
            "type": "pkg",
        }
        if package_settings:
            data["package settings"] = package_settings

        return await self.add(f"/pm/pkg/adom/{adom}", data=data)

    async def delete_package(
        self,
        adom: str,
        pkg: str,
    ) -> dict[str, Any]:
        """Delete a policy package.

        FNDN: DELETE /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.delete(f"/pm/pkg/adom/{adom}/{pkg}")

    async def clone_package(
        self,
        adom: str,
        pkg: str,
        new_name: str,
    ) -> dict[str, Any]:
        """Clone a policy package.

        FNDN: EXEC /securityconsole/package/clone
        """
        return await self.execute(
            "/securityconsole/package/clone",
            adom=adom,
            pkg=pkg,
            new_name=new_name,
        )

    async def assign_package(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign package to devices.

        FNDN: UPDATE /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.update(
            f"/pm/pkg/adom/{adom}/{pkg}",
            **{"scope member": scope}
        )

    # =========================================================================
    # Firewall Policies
    # =========================================================================

    async def list_firewall_policies(
        self,
        adom: str,
        pkg: str,
        fields: list[str] | None = None,
        filter: list | None = None,
        loadsub: int = 0,
        range: list[int] | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall policies in a package.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter
        if range:
            params["range"] = range

        result = await self.get(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        loadsub: int = 0,
    ) -> dict[str, Any]:
        """Get a specific firewall policy.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.get(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
            loadsub=loadsub,
        )

    async def get_firewall_policy_count(
        self,
        adom: str,
        pkg: str,
    ) -> int:
        """Get count of firewall policies in a package.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy with option=count
        """
        result = await self.get(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            option=["count"],
        )
        return result if isinstance(result, int) else 0

    async def create_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a new firewall policy.

        FNDN: ADD /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy
        """
        return await self.add(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            data=policy,
        )

    async def update_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a firewall policy.

        FNDN: UPDATE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
            **data,
        )

    async def delete_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
    ) -> dict[str, Any]:
        """Delete a firewall policy.

        FNDN: DELETE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
        )

    async def delete_firewall_policies(
        self,
        adom: str,
        pkg: str,
        policyids: list[int],
    ) -> dict[str, Any]:
        """Delete multiple firewall policies.

        FNDN: DELETE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy with filter
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            confirm=1,
            filter=["policyid", "in"] + policyids,
        )

    async def move_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        target: int,
        option: str = "before",
    ) -> dict[str, Any]:
        """Move a firewall policy before or after another policy.

        FNDN: EXEC /securityconsole/package/move
        """
        return await self.execute(
            "/securityconsole/move",
            adom=adom,
            pkg=pkg,
            policyid=policyid,
            target=target,
            option=option,
        )

    # =========================================================================
    # Firewall Objects - Addresses
    # =========================================================================

    async def list_addresses(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall address objects.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/address
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/address",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_address(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific firewall address.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/address/{name}")

    async def create_address(
        self,
        adom: str,
        address: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a firewall address object.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/address
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/address",
            data=address,
        )

    async def update_address(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a firewall address object.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/address/{name}",
            **data,
        )

    async def delete_address(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a firewall address object.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/address/{name}")

    # =========================================================================
    # Firewall Objects - Address Groups
    # =========================================================================

    async def list_address_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall address groups.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/addrgrp
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_address_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific address group.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}")

    async def create_address_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an address group.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/addrgrp
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp",
            data=group,
        )

    async def update_address_group(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an address group.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}",
            **data,
        )

    async def delete_address_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete an address group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}")

    # =========================================================================
    # Firewall Objects - Services
    # =========================================================================

    async def list_services(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List custom service objects.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/custom
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_service(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific service object.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}"
        )

    async def create_service(
        self,
        adom: str,
        service: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a custom service object.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/service/custom
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom",
            data=service,
        )

    async def update_service(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a service object.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}",
            **data,
        )

    async def delete_service(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a service object.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}"
        )

    # =========================================================================
    # Firewall Objects - Service Groups
    # =========================================================================

    async def list_service_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List service groups.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/group
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/service/group",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_service_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific service group.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/group/{name}
        """
        return await self.get(
            f"/pm/config/adom/{adom}/obj/firewall/service/group/{name}"
        )

    async def create_service_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a service group.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/service/group
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/service/group",
            data=group,
        )

    async def delete_service_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a service group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/service/group/{name}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/obj/firewall/service/group/{name}"
        )

    # =========================================================================
    # Workspace Mode (ADOM Locking)
    # =========================================================================

    async def lock_adom(self, adom: str) -> dict[str, Any]:
        """Lock an ADOM for editing (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/lock
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/lock")

    async def unlock_adom(self, adom: str) -> dict[str, Any]:
        """Unlock an ADOM (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/unlock
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/unlock")

    async def commit_adom(self, adom: str) -> dict[str, Any]:
        """Commit changes to an ADOM (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/commit
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/commit")

    # =========================================================================
    # Device Proxy - Execute Commands on Managed Devices
    # =========================================================================

    async def proxy_call(
        self,
        action: str,
        resource: str,
        target: list[str],
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute REST API call on managed device via FortiManager proxy.

        FNDN: EXEC /sys/proxy/json

        Args:
            action: HTTP method (get, post, put, delete)
            resource: FortiGate API endpoint (e.g., /api/v2/monitor/system/status)
            target: Target path ["/adom/{adom}/device/{device}"]
            data: Request data for POST/PUT operations

        Example:
            >>> # Get device status
            >>> result = await client.proxy_call(
            ...     action="get",
            ...     resource="/api/v2/monitor/system/status",
            ...     target=["/adom/root/device/FGT1"]
            ... )
        """
        params: dict[str, Any] = {
            "action": action,
            "resource": resource,
            "target": target,
        }
        if data:
            params["data"] = data

        return await self.execute("/sys/proxy/json", **params)

    # =========================================================================
    # CLI Script Management
    # =========================================================================

    async def list_scripts(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List CLI scripts in an ADOM.

        FNDN: GET /dvmdb/adom/{adom}/script
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/dvmdb/adom/{adom}/script", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_script(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific CLI script.

        FNDN: GET /dvmdb/adom/{adom}/script/{name}
        """
        return await self.get(f"/dvmdb/adom/{adom}/script/{name}")

    async def create_script(
        self,
        adom: str,
        script: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a CLI script.

        FNDN: ADD /dvmdb/adom/{adom}/script

        Script dict should contain:
            - name: Script name (required)
            - content: Script content (required)
            - type: cli, tcl, cligrp, tclgrp, jinja
            - target: device_database, remote_device, adom_database
            - desc: Description
        """
        return await self.add(f"/dvmdb/adom/{adom}/script", data=script)

    async def update_script(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a CLI script.

        FNDN: UPDATE /dvmdb/adom/{adom}/script/{name}
        """
        return await self.update(f"/dvmdb/adom/{adom}/script/{name}", **data)

    async def delete_script(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a CLI script.

        FNDN: DELETE /dvmdb/adom/{adom}/script/{name}
        """
        return await self.delete(f"/dvmdb/adom/{adom}/script/{name}")

    async def execute_script(
        self,
        adom: str,
        script: str,
        scope: list[dict[str, str]] | None = None,
        package: str | int | None = None,
    ) -> dict[str, Any]:
        """Execute a CLI script.

        FNDN: EXEC /dvmdb/adom/{adom}/script/execute

        Args:
            adom: ADOM name
            script: Script name to execute
            scope: Target devices [{"name": "device", "vdom": "global"}] for remote execution
                   Or device groups [{"name": "group_name"}] (no vdom means device group)
            package: Package name or OID for adom_database target scripts

        Returns:
            {"task": <task_id>} - Task ID for monitoring execution
        """
        data: dict[str, Any] = {
            "adom": adom,
            "script": script,
        }
        if scope:
            data["scope"] = scope
        if package:
            data["package"] = package

        return await self.execute(f"/dvmdb/adom/{adom}/script/execute", **data)

    async def get_script_log_latest(
        self,
        adom: str,
        device: str | None = None,
    ) -> dict[str, Any]:
        """Get latest script execution log.

        FNDN: GET /dvmdb/adom/{adom}/script/log/latest[/device/{device}]
        """
        url = f"/dvmdb/adom/{adom}/script/log/latest"
        if device:
            url += f"/device/{device}"
        return await self.get(url)

    async def get_script_log_summary(
        self,
        adom: str,
        device: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get script execution log summary.

        FNDN: GET /dvmdb/adom/{adom}/script/log/summary[/device/{device}]
        """
        url = f"/dvmdb/adom/{adom}/script/log/summary"
        if device:
            url += f"/device/{device}"
        result = await self.get(url)
        return result if isinstance(result, list) else [result] if result else []

    async def get_script_log_output(
        self,
        adom: str,
        log_id: int,
        device: str | None = None,
    ) -> dict[str, Any]:
        """Get specific script execution output.

        FNDN: GET /dvmdb/adom/{adom}/script/log/output/[device/{device}/]logid/{log_id}
        """
        if device:
            url = f"/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{log_id}"
        else:
            url = f"/dvmdb/adom/{adom}/script/log/output/logid/{log_id}"
        return await self.get(url)

    # =========================================================================
    # Provisioning Templates
    # =========================================================================

    async def list_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List all provisioning templates in an ADOM.

        FNDN: GET /pm/template/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/template/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific provisioning template.

        FNDN: GET /pm/template/adom/{adom}/{name}
        """
        return await self.get(f"/pm/template/adom/{adom}/{name}")

    async def list_system_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List system templates (devprof) in an ADOM.

        FNDN: GET /pm/devprof/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/devprof/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_system_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific system template.

        FNDN: GET /pm/devprof/adom/{adom}/{name}
        """
        return await self.get(f"/pm/devprof/adom/{adom}/{name}")

    async def assign_system_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign system template to devices.

        FNDN: ADD /pm/devprof/adom/{adom}/{template}/scope member

        Args:
            scope: [{"name": "device", "vdom": "root"}, ...]
        """
        return await self.add(
            f"/pm/devprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def unassign_system_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Unassign system template from devices.

        FNDN: DELETE /pm/devprof/adom/{adom}/{template}/scope member
        """
        return await self.delete(
            f"/pm/devprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def list_cli_template_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List CLI template groups.

        FNDN: GET /pm/config/adom/{adom}/obj/cli/template-group
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(
            f"/pm/config/adom/{adom}/obj/cli/template-group",
            **params
        )
        return result if isinstance(result, list) else [result] if result else []

    async def get_cli_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific CLI template group.

        FNDN: GET /pm/config/adom/{adom}/obj/cli/template-group/{name}
        """
        return await self.get(
            f"/pm/config/adom/{adom}/obj/cli/template-group/{name}"
        )

    async def create_cli_template_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a CLI template group.

        FNDN: ADD /pm/config/adom/{adom}/obj/cli/template-group
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/cli/template-group",
            data=group,
        )

    async def delete_cli_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a CLI template group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/cli/template-group/{name}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/obj/cli/template-group/{name}"
        )

    async def list_template_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List template groups (tmplgrp).

        FNDN: GET /pm/tmplgrp/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/tmplgrp/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific template group.

        FNDN: GET /pm/tmplgrp/adom/{adom}/{name}
        """
        return await self.get(f"/pm/tmplgrp/adom/{adom}/{name}")

    async def create_template_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a template group.

        FNDN: ADD /pm/tmplgrp/adom/{adom}
        """
        return await self.add(f"/pm/tmplgrp/adom/{adom}", data=group)

    async def assign_template_group(
        self,
        adom: str,
        template_group: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign template group to devices.

        FNDN: ADD /pm/tmplgrp/adom/{adom}/{template_group}/scope member
        """
        return await self.add(
            f"/pm/tmplgrp/adom/{adom}/{template_group}/scope member",
            data=scope,
        )

    async def validate_template(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Validate a template for devices.

        FNDN: EXEC /securityconsole/template/validate

        Args:
            pkg: Template path (e.g., "adom/demo/tmplgrp/template_group_001")
            scope: Target devices [{"name": "device", "vdom": "root"}]

        Returns:
            {"task": <task_id>} for monitoring validation
        """
        return await self.execute(
            "/securityconsole/template/validate",
            adom=adom,
            flag="json",
            pkg=pkg,
            scope=scope,
        )

    # =========================================================================
    # SD-WAN Templates
    # =========================================================================

    async def list_sdwan_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List SD-WAN templates (wanprof).

        FNDN: GET /pm/wanprof/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/wanprof/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_sdwan_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific SD-WAN template.

        FNDN: GET /pm/wanprof/adom/{adom}/{name}
        """
        return await self.get(f"/pm/wanprof/adom/{adom}/{name}")

    async def create_sdwan_template(
        self,
        adom: str,
        template: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an SD-WAN template.

        FNDN: ADD /pm/wanprof/adom/{adom}
        """
        return await self.add(f"/pm/wanprof/adom/{adom}", data=template)

    async def delete_sdwan_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete an SD-WAN template.

        FNDN: DELETE /pm/wanprof/adom/{adom}/{name}
        """
        return await self.delete(f"/pm/wanprof/adom/{adom}/{name}")

    async def assign_sdwan_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign SD-WAN template to devices.

        FNDN: ADD /pm/wanprof/adom/{adom}/{template}/scope member
        """
        return await self.add(
            f"/pm/wanprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def unassign_sdwan_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Unassign SD-WAN template from devices.

        FNDN: DELETE /pm/wanprof/adom/{adom}/{template}/scope member
        """
        return await self.delete(
            f"/pm/wanprof/adom/{adom}/{template}/scope member",
            data=scope,
        )
