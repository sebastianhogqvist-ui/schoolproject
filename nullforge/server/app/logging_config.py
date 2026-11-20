"""Structured JSON logging with mandatory secret redaction.

Redaction runs on the *formatted* JSON line, not just the message, so a secret
that rides along in an extra field or a ``repr`` is scrubbed too. Patterns are
deliberately broad: a false positive costs a masked string in a log, while a
false negative leaks a license key.
"""

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from app.config import Settings
from app.keys import ALPHABET, KEY_GROUP_SIZE, KEY_GROUPS, mask_license_key

REDACTED = "[REDACTED]"
HANDLER_NAME = "license-server-json"

_KEY_CLASS = f"[{ALPHABET}]{{{KEY_GROUP_SIZE}}}"
_LICENSE_KEY_RE = re.compile(rf"\b{_KEY_CLASS}(?:-{_KEY_CLASS}){{{KEY_GROUPS - 1}}}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*)"
    r"(?:bearer|basic|digest|token)?\s*[^\s\"',;)}\]]+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([a-z_]*(?:license_key|apikey|api_key|key_hash|hwid_hash|hwid|secret|pepper"
    r"|password_hash|password|token|jwt)[a-z_]*)(\"?\s*[=:]\s*\"?)"
    r"(?!\[REDACTED\])([^\s\"',;)}\]]+)"
)


def _mask_key_match(match: re.Match[str]) -> str:
    """Mask a license key found inside a log line, keeping only the last group."""
    return mask_license_key(match.group(0))


def redact(text: str) -> str:
    """Scrub license keys, tokens and secret-looking assignments from ``text``."""
    if not text:
        return text
    scrubbed = _LICENSE_KEY_RE.sub(_mask_key_match, text)
    scrubbed = _JWT_RE.sub(REDACTED, scrubbed)
    scrubbed = _AUTHORIZATION_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", scrubbed)
    scrubbed = _BEARER_RE.sub(f"Bearer {REDACTED}", scrubbed)
    scrubbed = _ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", scrubbed)
    return scrubbed


class RedactingFilter(logging.Filter):
    """Scrub the raw record arguments so handlers never see unredacted text."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Interpolate and redact the message in place; always keeps the record.

        ``args`` is cleared after interpolation so downstream handlers cannot
        re-run ``%``-formatting against already-redacted text.
        """
        try:
            record.msg = redact(record.getMessage())
            record.args = None
        except Exception:  # noqa: S110 - logging must never raise, and cannot log about itself
            pass
        return True


class JsonFormatter(logging.Formatter):
    """Render records as single-line JSON on stdout, redacted."""

    def format(self, record: logging.LogRecord) -> str:
        """Format one record as redacted JSON."""
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        for key, value in getattr(record, "__dict__", {}).items():
            if key.startswith("app_") and not key.startswith("app_internal"):
                payload[key[4:]] = value
        return redact(json.dumps(payload, default=str, ensure_ascii=False))


def configure_logging(settings: Settings, stream: Any = None) -> None:
    """Install the JSON handler on the root logger. Idempotent.

    Defaults to stdout; the CLI passes stderr so that machine-readable output
    such as freshly generated license keys stays uncontaminated.
    """
    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)

    for existing in list(root.handlers):
        if existing.get_name() == HANDLER_NAME:
            root.removeHandler(existing)

    handler = logging.StreamHandler(stream=sys.stdout if stream is None else stream)
    handler.set_name(HANDLER_NAME)
    handler.setLevel(settings.LOG_LEVEL)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger under the ``app`` namespace."""
    if name == "app" or name.startswith("app."):
        return logging.getLogger(name)
    return logging.getLogger(f"app.{name}")
