"""Shared response helpers for FortiManager MCP tools.

Provides a single structured error envelope and a free-text redactor that keeps
secrets out of error messages and logs. Ported from the FortiAnalyzer MCP's
``utils/responses.py`` (added in
https://github.com/rstierli/fortianalyzer-mcp/pull/17), adapted for FortiManager's
fields (``task_id``, ``package``, ``device``) instead of FAZ's (``tid``,
``logtype``).

Use ``error_response()`` from every tool error path so every error looks the
same to a caller. Use ``redact()`` when logging a free-text exception or filter
expression so a token / session-id / password in the upstream error doesn't
land in a log line or response.
"""

import re
from typing import Any

from fortimanager_mcp.utils.validation import MASK_VALUE, SENSITIVE_FIELDS

# Max length of a (redacted) human error message echoed back to the caller.
_MAX_MESSAGE_LEN = 500

# Secret-ish keys to scrub from free text as `key=value` / `key: value`. Drawn
# from SENSITIVE_FIELDS but excluding the most generic words ("key", "auth",
# "pass") so ordinary text is not mangled; the long-token rule below still masks
# real session ids/tokens.
_REDACT_KEYS = sorted(SENSITIVE_FIELDS - {"key", "auth", "pass"}, key=len, reverse=True)
_KV_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _REDACT_KEYS) + r")\b\s*[=:]\s*\"?([^\s\"&,;]+)\"?"
)
# Opaque token-like run (mirrors sanitize_for_logging's hex>20 heuristic).
_HEX_TOKEN_PATTERN = re.compile(r"\b[a-fA-F0-9]{20,}\b")


def redact(text: str) -> str:
    """Mask secrets in free text before logging or returning it.

    Scrubs ``key=value`` / ``key: value`` pairs whose key looks sensitive and long
    hexadecimal token-like runs. Normal text (e.g. a policy name or device ID) is
    left intact.
    """
    if not text:
        return text
    redacted = _KV_PATTERN.sub(lambda m: f"{m.group(1)}={MASK_VALUE}", text)
    redacted = _HEX_TOKEN_PATTERN.sub(MASK_VALUE, redacted)
    return redacted


def error_response(
    *,
    error: str,
    message: object,
    operation: str,
    adom: str | None = None,
    package: str | None = None,
    device: str | None = None,
    task_id: int | None = None,
    retry_count: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    """Build one structured error envelope used by every tool error path.

    ``error`` is a stable machine code (e.g. ``"validation_error"``,
    ``"adom_locked"``, ``"task_failed"``, ``"task_timeout"``, ``"network_error"``,
    ``"fmg_operation_failed"``). ``message`` is redacted and length-bounded human
    text. ``adom``/``package``/``device``/``task_id`` are included only when
    provided. Any additional context (e.g. ``preview_required``,
    ``recommendation``) can be passed via keyword and is merged verbatim.

    Mirrors the contract that
    `fortianalyzer-mcp#17 <https://github.com/rstierli/fortianalyzer-mcp/pull/17>`_
    established for FAZ, so a caller that has learned the FAZ-side shape sees the
    same fields on FMG errors.
    """
    msg = redact(str(message))
    if len(msg) > _MAX_MESSAGE_LEN:
        msg = msg[:_MAX_MESSAGE_LEN] + "... (truncated)"
    resp: dict[str, Any] = {
        "status": "error",
        "error": error,
        "message": msg,
        "operation": operation,
        "retry_count": retry_count,
    }
    if adom is not None:
        resp["adom"] = adom
    if package is not None:
        resp["package"] = package
    if device is not None:
        resp["device"] = device
    if task_id is not None:
        resp["task_id"] = task_id
    resp.update(extra)
    return resp
