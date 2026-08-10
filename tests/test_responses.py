"""Tests for the shared tool response helpers (error envelope + redaction).

Ported from
`fortianalyzer-mcp tests/test_responses.py <https://github.com/rstierli/fortianalyzer-mcp/blob/main/tests/test_responses.py>`_,
adapted for FortiManager's field names (``task_id``, ``package``, ``device``
instead of FAZ's ``tid``/``logtype``).
"""

from fortimanager_mcp.utils.responses import (
    error_response,
    redact,
    strip_device_credentials,
)
from fortimanager_mcp.utils.validation import MASK_VALUE


class TestRedact:
    """redact() scrubs secrets from free text before it is logged or returned."""

    def test_masks_token_key_value(self):
        out = redact("auth failed token=abcdef0123456789abcdef0123")
        assert "abcdef0123456789abcdef0123" not in out
        assert MASK_VALUE in out

    def test_masks_password_colon(self):
        out = redact("login error password: hunter2 retrying")
        assert "hunter2" not in out
        assert MASK_VALUE in out

    def test_masks_session_value(self):
        out = redact("session=ff77aabbcc1122334455667788 expired")
        assert "ff77aabbcc1122334455667788" not in out
        assert MASK_VALUE in out

    def test_masks_long_hex_session(self):
        out = redact("sid 9f8e7d6c5b4a3928170655443322110099aabbcc dropped")
        assert "9f8e7d6c5b4a3928170655443322110099aabbcc" not in out
        assert MASK_VALUE in out

    def test_leaves_normal_text_untouched(self):
        text = "policy id 42 in ADOM 'root' failed install on device FGT-VM01"
        assert redact(text) == text

    def test_empty_string(self):
        assert redact("") == ""


class TestErrorResponse:
    """error_response() builds one structured envelope for every error path."""

    def test_minimal_shape(self):
        r = error_response(
            error="fmg_operation_failed", message="boom", operation="install_package"
        )
        assert r["status"] == "error"
        assert r["error"] == "fmg_operation_failed"
        assert r["message"] == "boom"
        assert r["operation"] == "install_package"
        assert r["retry_count"] == 0
        # optional fields stay out unless supplied
        assert "adom" not in r
        assert "package" not in r
        assert "device" not in r
        assert "task_id" not in r

    def test_includes_adom_when_supplied(self):
        r = error_response(
            error="adom_locked",
            message="locked by another session",
            operation="commit_adom",
            adom="root",
        )
        assert r["adom"] == "root"

    def test_includes_install_context(self):
        r = error_response(
            error="task_failed",
            message="install failed",
            operation="install_package",
            adom="root",
            package="pkg-vpn",
            device="FGT-VM01",
            task_id=1234,
            retry_count=2,
        )
        assert r["adom"] == "root"
        assert r["package"] == "pkg-vpn"
        assert r["device"] == "FGT-VM01"
        assert r["task_id"] == 1234
        assert r["retry_count"] == 2

    def test_includes_extras_verbatim(self):
        r = error_response(
            error="preview_required",
            message="install requires preview first",
            operation="install_package",
            recommendation="run preview_install first",
            preview_required=True,
        )
        assert r["recommendation"] == "run preview_install first"
        assert r["preview_required"] is True

    def test_redacts_message(self):
        r = error_response(
            error="fmg_operation_failed",
            message="failed token=abcdef0123456789abcdef0123",
            operation="get_address",
        )
        assert "abcdef0123456789abcdef0123" not in r["message"]
        assert MASK_VALUE in r["message"]

    def test_truncates_long_message(self):
        r = error_response(
            error="fmg_operation_failed", message="x" * 2000, operation="get_address"
        )
        assert len(r["message"]) < 600


class TestStripDeviceCredentials:
    """A device's admin password must not reach a caller from a READ.

    add_device and add_devices_bulk have always stripped these from the
    object FortiManager echoes back. No read path did, so the stored
    password came out of list_devices, get_device, search_devices and
    get_device_status. FortiManager treats `fields` as a hint rather than
    a bound, so a narrow field list does not keep it out either.
    """

    def test_both_spellings_are_removed(self):
        record = {
            "name": "FGT-01",
            "adm_usr": "admin",
            "adm_pass": "s3cret",
            "adm_passwd": "s3cret",
        }

        out = strip_device_credentials(record)

        assert out == {"name": "FGT-01", "adm_usr": "admin"}
        assert "s3cret" not in repr(out)

    def test_key_is_matched_however_it_is_spelled(self):
        """FMG has answered with hyphenated and title-cased keys elsewhere."""
        record = {"ADM_PASS": "s3cret", "adm-passwd": "s3cret", "Adm Pass": "s3cret", "ok": 1}

        out = strip_device_credentials(record)

        assert out == {"ok": 1}
        assert "s3cret" not in repr(out)

    def test_it_recurses_through_lists_and_nesting(self):
        payload = {
            "devices": [
                {"name": "FGT-01", "adm_pass": "s3cret"},
                {"name": "FGT-02", "vdom": [{"name": "root", "adm_pass": "s3cret"}]},
            ]
        }

        out = strip_device_credentials(payload)

        assert "s3cret" not in repr(out)
        assert out["devices"][0]["name"] == "FGT-01"
        assert out["devices"][1]["vdom"][0]["name"] == "root"

    def test_everything_else_survives_untouched(self):
        """Narrow on purpose: this is not sanitize_for_logging.

        That helper masks any key containing "key", "auth", "sid" or
        "session" plus any hex run over 20 characters, which would mangle
        legitimate device fields.
        """
        record = {
            "name": "FGT-01",
            "sn": "FGVM020000123456",
            "oid": 194,
            "uuid": "200ac24666a551f1fcb94e7ebd5398d7",
            "mgmt_mode": 3,
            "conn_status": 1,
        }

        assert strip_device_credentials(record) == record

    def test_the_tunnel_psk_and_private_key_go_too(self):
        """These were survivors in the first version of this test.

        Asserting that `psk` comes back unchanged treats the FGFM tunnel
        pre-shared key as a benign field, and would have blocked whoever
        later added it to the strip set. It is a secret; so is
        `private_key`. `private_key_status` is not, and stays.
        """
        record = {
            "name": "FGT-01",
            "psk": "s3cret",
            "private_key": "s3cret",
            "private_key_status": 1,
        }

        out = strip_device_credentials(record)

        assert "s3cret" not in repr(out)
        assert out == {"name": "FGT-01", "private_key_status": 1}

    def test_the_depth_bound_fails_closed(self):
        """Past the bound the secret must not be published.

        The first version returned the subtree unchanged there, so a
        credential nested deeper than the bound came straight back out of
        the function whose job is removing it. "Too deep to check" is not
        a reason to hand it over. Real dvmdb records are two or three
        levels deep, so nothing legitimate reaches this.
        """
        deep: dict = {"adm_pass": "s3cret"}
        for _ in range(40):
            deep = {"nested": deep}

        out = strip_device_credentials(deep)

        assert "s3cret" not in repr(out)
