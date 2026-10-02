from __future__ import annotations

import logging
import re
from threading import RLock
from typing import Iterable


_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(
        r"(?i)\b(access[_-]?token|refresh[_-]?token|password|passphrase|"
        r"client[_-]?secret|api[_-]?key|authorization)\s*[:=]\s*"
        r"([^\s,;]+)"
    ),
)


def redact_text(value: str, additional_secrets: Iterable[str] = ()) -> str:
    redacted = value
    for pattern in _PATTERNS:
        if pattern.pattern.lower().startswith("(?i)\\bbearer"):
            redacted = pattern.sub("Bearer <redacted>", redacted)
        else:
            redacted = pattern.sub(lambda m: f"{m.group(1)}=<redacted>", redacted)
    for secret in sorted((s for s in additional_secrets if s), key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    return redacted


class RedactingFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._known_secrets: set[str] = set()
        self._lock = RLock()

    def add_secret(self, value: str) -> None:
        if value:
            with self._lock:
                self._known_secrets.add(value)

    def filter(self, record: logging.LogRecord) -> bool:
        with self._lock:
            known = tuple(self._known_secrets)
        record.msg = redact_text(record.getMessage(), known)
        record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> RedactingFilter:
    handler = logging.StreamHandler()
    redactor = RedactingFilter()
    handler.addFilter(redactor)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    return redactor
