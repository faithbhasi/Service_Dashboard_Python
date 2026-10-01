"""Logging: console plus a daily rolling file, a correlation id on every line, and secrets redacted before any handler sees them."""
from __future__ import annotations

import logging
import re
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from .request_context import correlation_id

MASK = "[REDACTED]"
_SENSITIVE_NAME = re.compile(r"pass(word|wd)?$|pwd|secret|token|authorization|cookie|apikey|unicodepwd|credential", re.IGNORECASE)
_INLINE_SECRET = re.compile(
    r"""(?P<key>["']?[\w.-]*(?:password|passwd|pwd|secret|token|authorization|apikey|unicodepwd)[\w.-]*["']?\s*[=:]\s*)"""
    r"""(?:(?:Bearer|Basic)\s+[^\s,;&}\]]+|"[^"]*"|'[^']*'|[^\s,;&}\]]+)""",
    re.IGNORECASE)


def redact_text(s: str) -> str:
    return _INLINE_SECRET.sub(lambda m: m.group("key") + MASK, s)


def redact_value(name: str | None, value):
    if name and _SENSITIVE_NAME.search(name):
        return MASK
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(k if isinstance(k, str) else None, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(None, v) for v in value)
    return value


class SensitiveDataFilter(logging.Filter):
    """Redacts anything that looks like a password, secret or token from the message and its arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # a bad format string must never lose the log line
            msg = str(record.msg)
        record.msg = redact_text(msg)
        record.args = None
        for key in list(record.__dict__):
            if key not in logging.LogRecord("", 0, "", 0, "", None, None).__dict__ and key not in ("message", "asctime"):
                record.__dict__[key] = redact_value(key, record.__dict__[key])
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        return True


class CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = correlation_id() or "-"
        return True


def configure_logging(log_dir: Path, level: int = logging.INFO, extra_handlers: list[logging.Handler] | None = None) -> logging.Logger:
    """Sets up the 'sd' logger tree. Safe to call again (for tests): it replaces its own handlers."""
    logger = logging.getLogger("sd")
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    logger.setLevel(level)
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter("[%(asctime)s %(levelname).3s] %(correlation_id)s %(message)s", "%H:%M:%S"))
    handlers: list[logging.Handler] = [console]
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = TimedRotatingFileHandler(log_dir / "app.log", when="midnight", backupCount=30, encoding="utf-8", delay=True)
        fh.suffix = "%Y%m%d"
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname).3s] %(correlation_id)s %(message)s"))
        handlers.append(fh)
    except OSError:
        pass
    handlers += extra_handlers or []
    for h in handlers:
        h.addFilter(SensitiveDataFilter())
        h.addFilter(CorrelationFilter())
        logger.addHandler(h)
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger("sd." + name)
