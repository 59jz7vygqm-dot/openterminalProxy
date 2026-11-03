"""Entry point: ``python -m otproxy``.

Configuration errors are reported as a single line and exit 2 -- a container
that cannot be configured should not come up half-working.
"""

from __future__ import annotations

import sys

import uvicorn

from . import config, log
from .app import create_app


USAGE = """usage: python -m otproxy [--aimon-test [--dry-run]]

  (no arguments)   run the proxy
  --aimon-test     send one example batch to AIMON_URL and print the answer
  --dry-run        with --aimon-test: let aimonitor validate without storing
"""


def _aimon_test(settings: "config.Settings", dry_run: bool) -> int:
    """Section 5 of the integration brief: prove the connection, once."""
    import asyncio

    from . import __version__
    from .aimon import AimonConfig, example_snapshot, self_test

    aimon = AimonConfig.from_env(settings.port, __version__)
    if not aimon.enabled:
        print("AIMON_URL is not set, so there is nothing to test against.", file=sys.stderr)
        return 2
    snapshot = example_snapshot(settings.max_sandboxes, settings.pool_size)
    try:
        status, body = asyncio.run(self_test(aimon, snapshot, dry_run=dry_run))
    except Exception as exc:  # noqa: BLE001 -- a self-test reports, it does not raise
        print(f"POST {aimon.endpoint} -> failed: {exc}", file=sys.stderr)
        return 1
    suffix = "?dry_run=1" if dry_run else ""
    print(f"POST {aimon.endpoint}{suffix} -> {status} {body}")
    return 0 if 200 <= status < 300 else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    unknown = [item for item in arguments if item not in ("--aimon-test", "--dry-run", "--help", "-h")]
    if unknown or "--help" in arguments or "-h" in arguments:
        print(USAGE, file=sys.stderr if unknown else sys.stdout)
        return 64 if unknown else 0

    try:
        settings = config.load()
    except config.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    log.setup(settings.log_level, settings.log_json)

    if "--aimon-test" in arguments:
        return _aimon_test(settings, dry_run="--dry-run" in arguments)
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
