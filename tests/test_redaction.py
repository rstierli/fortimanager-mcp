"""Shared redaction helpers: the secret-field strip and the device-message scrub."""

from fortimanager_mcp.utils.redaction import safe_device_message, strip_secret_fields

SECRETS = frozenset({"password", "eap-password"})


class TestStripSecretFields:
    def test_strips_at_any_depth(self) -> None:
        data = {
            "name": "port1",
            "password": "ENC x",
            "health-check": [{"name": "hc", "password": "y", "server": ["192.0.2.1"]}],
            "nested": {"deeper": [{"eap-password": "z", "keep": 1}]},
        }
        assert strip_secret_fields(data, SECRETS) == {
            "name": "port1",
            "health-check": [{"name": "hc", "server": ["192.0.2.1"]}],
            "nested": {"deeper": [{"keep": 1}]},
        }

    def test_scalars_and_lists_pass_through(self) -> None:
        assert strip_secret_fields("password", SECRETS) == "password"
        assert strip_secret_fields([1, None], SECRETS) == [1, None]

    def test_keys_match_exactly(self) -> None:
        """FortiOS names, not normalized: ``password-expire`` is not a secret."""
        data = {"password-expire": "2026-01-01", "Password": "kept-as-is"}
        assert strip_secret_fields(data, SECRETS) == data


class TestSafeDeviceMessage:
    def test_plain_message_is_kept(self) -> None:
        assert safe_device_message("Invalid url") == "Invalid url"

    def test_empty_falls_back(self) -> None:
        assert safe_device_message(None) == "device proxy error"
        assert safe_device_message("  ", default="x") == "x"

    def test_paths_secrets_and_newlines_are_removed(self) -> None:
        message = "branch1(228) error: /api/v2/cmdb/x failed\npassword=hunter2\n"
        out = safe_device_message(message)
        assert "/api/" not in out
        assert "hunter2" not in out
        assert "\n" not in out

    def test_length_is_bounded(self) -> None:
        out = safe_device_message("x " * 1000)
        assert len(out) <= 300
        assert out.endswith("...")
