"""Entry point: ``python -m otproxy``.

Configuration errors are reported as a single line and exit 2 -- a container
that cannot be configured should not come up half-working.
"""

from __future__ import annotations

import sys

import uvicorn

from . import config, log
from .app import create_app


def main(argv: list[str] | None = None) -> int:
    try:
        settings = config.load()
    except config.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    log.setup(settings.log_level, settings.log_json)
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,            # our own logging, one format for everything
        access_log=False,           # the sandbox logs requests; this one would duplicate them
        timeout_keep_alive=75,
        ws_max_size=None,
        proxy_headers=False,        # nothing in front of this that we trust
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
