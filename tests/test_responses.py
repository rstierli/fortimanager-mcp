"""Tests for the shared tool response helpers (error envelope + redaction).

Ported from
`fortianalyzer-mcp tests/test_responses.py <https://github.com/rstierli/fortianalyzer-mcp/blob/main/tests/test_responses.py>`_,
adapted for FortiManager's field names (``task_id``, ``package``, ``device``
instead of FAZ's ``tid``/``logtype``).
"""

from fortimanager_mcp.utils.responses import error_response, redact
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
