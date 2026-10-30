"""Logging setup.  One rule: secrets never reach a log line.

The proxy handles two kinds of secret -- the bearer key Open WebUI sends and the
per-container key it generates -- and both would otherwise end up in a log the
moment somebody logs a request header or a container's environment.  Nothing in
this package logs either, and :func:`redact` exists for the places that build a
message out of foreign data.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Dict

LOGGER_NAME = "otproxy"


class _JsonFormatter(logging.Formatter):
    """One JSON object per line, for whatever collects the container's stdout."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup(level: str = "INFO", as_json: bool = False) -> logging.Logger:
    handler = logging.StreamHandler(stream=sys.stdout)
    if as_json:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
                datefmt="%H:%M:%S",
            )
        )
    root = logging.getLogger(LOGGER_NAME)
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))
    root.propagate = False
    return root


def get(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


def redact(text: str, *secrets: str) -> str:
    """Replace any of *secrets* found in *text* with a marker."""
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "<redacted>")
    return text
