"""Reporting the proxy's state to an aimonitor instance.

Two rules shape this module, and the first one wins every time:

**The data path must not get slower or less reliable.**  Nothing here is ever
awaited by a request or by the lifecycle logic.  Events are appended to a
bounded deque and the sending happens in one background task.  If aimonitor is
down, slow, or answering nonsense, the worst that happens is that batches are
dropped out of the buffer -- never that a user waits.

**Nothing is invented.**  A field this proxy does not measure is left out, so
that aimonitor can show it as missing.  What this proxy means by an "instance"
is spelled out in :meth:`SandboxManager.telemetry_snapshot`: one container
serves exactly one user, so instance and session are the same thing here, and
the mapping is written down rather than guessed at.

Switched off entirely unless ``AIMON_URL`` is set.
"""

from __future__ import annotations

import json
import os
import random
import socket
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import httpx

from . import log

logger = log.get("aimon")

#: Per the interface: everything but node and service is optional.
SCALER_PATH = "/api/v1/ingest/scaler"

EVENT_KINDS = ("scale.up", "scale.down", "scale.blocked", "scale.failed", "instance.unhealthy")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_float(name: str, default: float, minimum: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number, using %s", name, raw, default)
        return default
    return max(minimum, value)


@dataclass(frozen=True)
class AimonConfig:
    url: str = ""
    token: str = ""
    node: str = ""
    service_key: str = ""
    service_kind: str = "openterminal_proxy"
    service_name: str = "OpenTerminal Autoscaler"
    service_base_url: str = ""
    version: str = ""
    interval: float = 10.0
    timeout: float = 5.0
    buffer_seconds: float = 600.0

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    @property
    def endpoint(self) -> str:
        return f"{self.url.rstrip('/')}{SCALER_PATH}"

    @property
    def buffered_batches(self) -> int:
        """How many batches the ring buffer holds -- about buffer_seconds of them."""
        return max(1, int(self.buffer_seconds / max(1.0, self.interval)))

    @staticmethod
    def from_env(port: int = 8800, version: str = "") -> "AimonConfig":
        url = _env("AIMON_URL")
        if not url:
            return AimonConfig()
        node = _env("AIMON_NODE")
        if not node:
            # Inside a container the hostname is the container id, which is not
            # a machine name; say so rather than silently reporting it.
            node = socket.gethostname()
            logger.warning(
                "AIMON_NODE is not set, reporting node.name=%r (the hostname). "
                "Set it to the machine's name.", node,
            )
        return AimonConfig(
            url=url,
            token=_env("AIMON_TOKEN"),
            node=node,
            service_key=_env("AIMON_SERVICE_KEY") or f"openterminal-proxy@{node}:{port}",
            service_base_url=_env("AIMON_SERVICE_BASE_URL"),
            version=version,
            interval=_env_float("AIMON_INTERVAL", 10.0, 1.0),
            timeout=_env_float("AIMON_TIMEOUT", 5.0, 0.5),
            buffer_seconds=_env_float("AIMON_BUFFER_SECONDS", 600.0, 10.0),
        )


@dataclass
class HostSampler:
    """Host CPU and memory, read from /proc.  Measured, not estimated.

    Inside a container /proc/stat and /proc/meminfo describe the host, which is
    what an operator wants for the machine the sandboxes run on.  Anything that
    cannot be read is left out of the payload.
    """

    _previous: Optional[Tuple[float, float]] = None

    def sample(self) -> Dict[str, Any]:
        usage: Dict[str, Any] = {}
        cpu = self._cpu_percent()
        if cpu is not None:
            usage["cpu_pct"] = round(cpu, 1)
        memory = self._memory()
        if memory:
            usage.update(memory)
        return usage

    def _cpu_percent(self) -> Optional[float]:
        try:
            with open("/proc/stat", "r", encoding="ascii") as handle:
                fields = handle.readline().split()
        except (OSError, ValueError):
            return None
        if len(fields) < 5 or fields[0] != "cpu":
            return None
        try:
            values = [float(value) for value in fields[1:]]
        except ValueError:
            return None
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0.0)
        previous, self._previous = self._previous, (total, idle)
        if previous is None:
            return None            # the first sample only establishes a baseline
        total_delta = total - previous[0]
        idle_delta = idle - previous[1]
        if total_delta <= 0:
            return None
        return max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))

    def _memory(self) -> Dict[str, int]:
        try:
            with open("/proc/meminfo", "r", encoding="ascii") as handle:
                lines = handle.readlines()
        except OSError:
            return {}
        values: Dict[str, int] = {}
        for line in lines:
            key, _, rest = line.partition(":")
            parts = rest.split()
            if key in ("MemTotal", "MemAvailable") and parts:
                try:
                    values[key] = int(parts[0]) * 1024
                except ValueError:
                    return {}
        if "MemTotal" not in values or "MemAvailable" not in values:
            return {}
        return {
            "mem_total_bytes": values["MemTotal"],
            "mem_used_bytes": values["MemTotal"] - values["MemAvailable"],
        }


class Telemetry:
    """Collects events, builds batches, and sends them without ever blocking."""

    def __init__(
        self,
        config: AimonConfig,
        snapshot: Optional[Callable[[], Dict[str, Any]]] = None,
        *,
        client: Optional[httpx.AsyncClient] = None,
        sleep: Optional[Callable[[float], Any]] = None,
    ) -> None:
        self.config = config
        self._snapshot = snapshot
        self._events: Deque[Dict[str, Any]] = deque(maxlen=2048)
        self._pending: Deque[Dict[str, Any]] = deque(maxlen=config.buffered_batches)
        self._host = HostSampler()
        self._last_scale_reason = ""
        self._failures = 0
        self._schema_complaint = ""
        self._dropped_batches = 0
        self._sent_batches = 0
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep
        self._task: Optional[Any] = None
        self._closing = False

    # ------------------------------------------------------------------
    # what the rest of the proxy calls
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def event(
        self,
        kind: str,
        title: str,
        *,
        severity: str = "info",
        detail: Optional[Dict[str, Any]] = None,
        dedup_key: Optional[str] = None,
        reason: str = "",
    ) -> None:
        """Record one event.  Returns immediately; nothing is sent from here."""
        if not self.enabled:
            return
        if kind not in EVENT_KINDS:          # a typo must not reach the server
            logger.debug("ignoring unknown event kind %r", kind)
            return
        if reason:
            self._last_scale_reason = reason
        payload: Dict[str, Any] = {
            "ts": int(time.time()),
            "kind": kind,
            "severity": severity,
            "title": title,
            "service": self.config.service_key,
        }
        body = dict(detail or {})
        if reason:
            body.setdefault("reason", reason)
        if body:
            payload["detail"] = body
        if dedup_key:
            payload["dedup_key"] = dedup_key
        self._events.append(payload)

    @property
    def last_scale_reason(self) -> str:
        return self._last_scale_reason

    # ------------------------------------------------------------------
    # the background task
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if not self.enabled or self._task is not None:
            return
        import asyncio

        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout, connect=min(2.0, self.config.timeout)),
                trust_env=False,
            )
        logger.info(
            "reporting to %s every %.0fs as node=%s service=%s",
            self.config.endpoint, self.config.interval, self.config.node, self.config.service_key,
        )
        self._task = asyncio.create_task(self._loop(), name="otproxy-aimon")

    async def close(self) -> None:
        self._closing = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except BaseException:  # noqa: BLE001 -- shutdown path, nothing may escape
                pass
            self._task = None
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def _loop(self) -> None:
        import asyncio

        while not self._closing:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- telemetry must never take the proxy down
                logger.warning("telemetry cycle failed: %s", exc)
            await self._wait(self.config.interval)

    async def _wait(self, seconds: float) -> None:
        import asyncio

        if self._sleep is not None:
            await self._sleep(seconds)
        else:
            await asyncio.sleep(seconds)

    async def _tick(self) -> None:
        self._pending.append(self.build_batch())
        await self.flush()

    # ------------------------------------------------------------------
    # building
    # ------------------------------------------------------------------

    def build_batch(self) -> Dict[str, Any]:
        """One request body: the current state plus the events since the last one."""
        state: Dict[str, Any] = {}
        instances: List[Dict[str, Any]] = []
        if self._snapshot is not None:
            try:
                snapshot = self._snapshot() or {}
                state = dict(snapshot.get("state") or {})
                instances = list(snapshot.get("instances") or [])
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not read the proxy's state: %s", exc)
        state.update(self._host.sample())
        if self._last_scale_reason:
            state.setdefault("last_scale_reason", self._last_scale_reason)

        events: List[Dict[str, Any]] = []
        while self._events:
            events.append(self._events.popleft())

        service: Dict[str, Any] = {
            "key": self.config.service_key,
            "kind": self.config.service_kind,
            "name": self.config.service_name,
        }
        if self.config.service_base_url:
            service["base_url"] = self.config.service_base_url
        if self.config.version:
            service["version"] = self.config.version

        batch: Dict[str, Any] = {
            "node": {"name": self.config.node},
            "service": service,
            "ts": int(time.time()),
        }
        if state:
            batch["state"] = state
        if instances:
            batch["instances"] = instances
        if events:
            batch["events"] = events
        return batch

    # ------------------------------------------------------------------
    # sending
    # ------------------------------------------------------------------

    def backoff_delay(self, failures: Optional[int] = None) -> float:
        """1, 2, 4, 8 ... capped at 60, with jitter."""
        count = self._failures if failures is None else failures
        base = min(60.0, 2.0 ** max(0, count - 1))
        return base * (0.8 + random.random() * 0.4)

    async def flush(self) -> None:
        """Try to deliver the buffer.  Keeps what it could not send."""
        if self._client is None or not self._pending:
            return
        while self._pending:
            batch = self._pending[0]
            outcome, retry_after = await self._post(batch)
            if outcome == "sent":
                self._pending.popleft()
                self._sent_batches += 1
                self._failures = 0
                continue
            if outcome == "drop":
                self._pending.popleft()
                self._dropped_batches += 1
                self._failures = 0
                continue
            # keep: stop here, the loop tries again after a backoff
            self._failures += 1
            await self._wait(retry_after if retry_after is not None else self.backoff_delay())
            return

    async def _post(self, batch: Dict[str, Any]) -> Tuple[str, Optional[float]]:
        """Send one batch.  Returns ("sent"|"drop"|"keep", retry_after)."""
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        try:
            response = await self._client.post(  # type: ignore[union-attr]
                self.config.endpoint, content=json.dumps(batch).encode("utf-8"), headers=headers
            )
        except Exception as exc:  # noqa: BLE001 -- httpx raises many shapes; all mean "keep"
            logger.debug("aimonitor unreachable: %s", exc)
            return "keep", None

        status = response.status_code
        if 200 <= status < 300:
            return "sent", None
        if status == 429:
            return "keep", _retry_after(response.headers.get("retry-after"))
        if 400 <= status < 500:
            # The schema does not match, or the token is wrong. Retrying cannot
            # help, so the batch goes -- and it is said once, not every cycle.
            complaint = f"{status}:{response.text[:200]}"
            if complaint != self._schema_complaint:
                self._schema_complaint = complaint
                logger.error(
                    "aimonitor refused the payload with %s and will not be asked again with it: %s",
                    status, response.text[:400],
                )
            return "drop", None
        return "keep", None

    # ------------------------------------------------------------------
    # reporting on ourselves
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "endpoint": self.config.endpoint if self.enabled else None,
            "buffered_batches": len(self._pending),
            "buffer_limit": self.config.buffered_batches,
            "queued_events": len(self._events),
            "sent_batches": self._sent_batches,
            "dropped_batches": self._dropped_batches,
            "consecutive_failures": self._failures,
        }


class NoTelemetry:
    """What the proxy uses when AIMON_URL is not set: nothing happens."""

    enabled = False
    last_scale_reason = ""

    def event(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def stats(self) -> Dict[str, Any]:
        return {"enabled": False}


async def self_test(
    config: AimonConfig,
    snapshot: Dict[str, Any],
    *,
    dry_run: bool = False,
    client: Optional[httpx.AsyncClient] = None,
) -> Tuple[int, str]:
    """Send one example batch and return ``(status, body)``.

    Used by ``python -m otproxy --aimon-test`` so the connection can be checked
    without waiting for real load.  The batch is marked as a self-test in its
    event title; with *dry_run* the server validates it and stores nothing.
    """
    telemetry = Telemetry(config, snapshot=lambda: snapshot, client=client)
    telemetry.event(
        "scale.up",
        "Self-test from openterminal-proxy (no real scale happened)",
        detail={"from": 0, "to": 1, "self_test": True},
        reason="aimon self-test",
    )
    batch = telemetry.build_batch()
    headers = {"Content-Type": "application/json"}
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    endpoint = config.endpoint + ("?dry_run=1" if dry_run else "")
    owns = client is None
    http = client or httpx.AsyncClient(
        timeout=httpx.Timeout(config.timeout, connect=min(2.0, config.timeout)), trust_env=False
    )
    try:
        response = await http.post(endpoint, content=json.dumps(batch).encode("utf-8"), headers=headers)
        return response.status_code, response.text.strip()
    finally:
        if owns:
            await http.aclose()


def example_snapshot(max_sandboxes: int, pool_size: int) -> Dict[str, Any]:
    """A batch body for the self-test: real limits, zeroed counts."""
    return {
        "state": {
            "instances_running": 0,
            "instances_desired": pool_size,
            "instances_min": pool_size,
            "instances_max": max_sandboxes,
            "instances_starting": 0,
            "instances_draining": 0,
            "sessions_active": 0,
            "sessions_per_instance_target": 1,
            "sessions_queued": 0,
            "scale_cooldown_s_remaining": 0,
        },
        "instances": [],
    }


def _retry_after(value: Optional[str]) -> Optional[float]:
    """Seconds from a Retry-After header, if it carries a number."""
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return None       # an HTTP-date is not handled; the backoff takes over
