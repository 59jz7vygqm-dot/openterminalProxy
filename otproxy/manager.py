"""Lifecycle: which user has a sandbox, when one starts, and when it goes away.

This is where "scales automatically" actually lives, and it is deliberately
boring:

* A sandbox is created on the first request that needs it, and nothing is
  running for a user who is not working.
* A warm container can be kept ready so the first request of a session does not
  wait for a container to boot.  Open WebUI gives ``/files/cwd`` five seconds
  before it gives up on it, and a cold start does not fit in five seconds.
* A sandbox is removed once it has been idle for ``IDLE_TIMEOUT``, and in any
  case after ``MAX_LIFETIME``.
* There is a hard ceiling (``MAX_SANDBOXES``).  At the ceiling the longest-idle
  sandbox is evicted to make room; if nothing is idle enough, the request is
  refused with 503 and a Retry-After rather than overcommitting the host.

The containers are the state.  This class keeps a cache of them and re-reads it
from Docker at startup, so a restarted proxy picks up running sandboxes instead
of orphaning them -- and two replicas on one host converge on the same set.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from . import log
from .config import Policy, Settings
from .dockerapi import DockerError
from .ids import Scope
from .netpool import SubnetPool
from .sandbox import ROLE_WARM, DockerSandboxBackend, Sandbox, SandboxError

logger = log.get("manager")


class CapacityError(RuntimeError):
    """The host is full and nothing could be evicted."""

    def __init__(self, retry_after: int = 30) -> None:
        super().__init__("no sandbox slot available")
        self.retry_after = retry_after


@dataclass
class IsolationReport:
    """What a sandbox could actually reach, measured from inside one."""

    internet: str = "unknown"
    host: str = "unknown"
    detail: str = ""

    @property
    def internet_blocked(self) -> bool:
        return self.internet == "blocked"

    @property
    def host_blocked(self) -> bool:
        return self.host == "blocked"

    @property
    def ok(self) -> bool:
        return self.internet_blocked and self.host_blocked


class SandboxManager:
    def __init__(self, settings: Settings, backend: Optional[DockerSandboxBackend] = None) -> None:
        self.settings = settings
        self.backend = backend or DockerSandboxBackend(settings)
        self._sandboxes: Dict[str, Sandbox] = {}
        self._warm: List[Sandbox] = []
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()
        self._cache_lock = asyncio.Lock()
        self._tasks: List[asyncio.Task] = []
        self._closing = False
        self._schema_cache: Dict[str, Tuple[float, Any]] = {}
        self._isolation: Optional[IsolationReport] = None
        self._stats = {"created": 0, "claimed_warm": 0, "evicted": 0, "reaped": 0, "refused": 0, "failed": 0}
        self._probe = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=2.0), trust_env=False, follow_redirects=False
        )

    # ------------------------------------------------------------------
    # start / stop
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if not await self.backend.docker.ping():
            raise SandboxError(
                f"cannot reach the Docker API at {self.backend.docker.description}: "
                "mount the socket into this container, or set DOCKER_HOST"
            )
        version = await self.backend.docker.version()
        logger.info("docker %s (API %s)", version.get("Version", "?"), version.get("ApiVersion", "?"))
        await self.backend.resolve_self()

        adopted, warm = await self.backend.adopt_all()
        for sandbox in adopted:
            self._sandboxes[sandbox.key] = sandbox
        self._warm = warm
        if adopted or warm:
            logger.info("adopted %d running sandbox(es) and %d warm container(s)", len(adopted), len(warm))

        if self.settings.network_mode == "shared":
            await self.backend.ensure_network(None, self.settings.shared_network)

        if self.settings.require_isolation:
            # The strict setting means the proxy must not come up at all when a
            # sandbox can still reach something.  That can only be answered by
            # starting one and asking from inside, so it happens here rather
            # than on the first user's request.
            await self._startup_isolation_check()

        self._tasks.append(asyncio.create_task(self._reaper_loop(), name="otproxy-reaper"))
        if self.settings.pool_size:
            self._tasks.append(asyncio.create_task(self._pool_loop(), name="otproxy-pool"))

    async def _startup_isolation_check(self) -> None:
        sandbox, temporary = await self._introspection_sandbox()
        try:
            await self._verify_isolation(sandbox)
        finally:
            if temporary:
                await self._destroy_quietly(sandbox)

    async def close(self) -> None:
        self._closing = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 -- shutdown path
                pass
        self._tasks.clear()
        if self.settings.stop_on_shutdown:
            for sandbox in list(self._sandboxes.values()) + list(self._warm):
                try:
                    await self.backend.destroy(sandbox)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("could not remove %s during shutdown: %s", sandbox.name, exc)
        await self._probe.aclose()
        await self.backend.docker.close()

    # ------------------------------------------------------------------
    # the hot path
    # ------------------------------------------------------------------

    def _lock(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = self._locks[key] = asyncio.Lock()
        return lock

    async def acquire(self, scope: Scope, policy: Optional[Policy] = None) -> Sandbox:
        """Return a ready sandbox for *scope*, starting one if needed.

        Concurrent requests from the same user wait on one lock, so a burst of
        tool calls at the start of a chat produces one container, not five.
        """
        key = scope.key
        sandbox = self._sandboxes.get(key)
        if sandbox is not None and sandbox.ready:
            sandbox.touch()
            return sandbox

        async with self._lock(key):
            sandbox = self._sandboxes.get(key)
            if sandbox is not None:
                if sandbox.ready:
                    sandbox.touch()
                    return sandbox
                if await self._still_running(sandbox):
                    await self._wait_ready(sandbox)
                    sandbox.touch()
                    return sandbox
                logger.warning("sandbox %s died, replacing it", sandbox.name)
                await self._forget(sandbox, destroy=True)

            if self.settings.require_isolation and self._isolation is not None and not self._isolation.ok:
                raise SandboxError(
                    "refusing to hand out a sandbox: the isolation self-check failed "
                    f"(internet={self._isolation.internet} host={self._isolation.host}) "
                    "and OTPROXY_REQUIRE_ISOLATION is set"
                )
            await self._make_room()
            sandbox = await self._provision(scope, policy)
            self._sandboxes[key] = sandbox
            try:
                await self._wait_ready(sandbox)
            except Exception:
                await self._forget(sandbox, destroy=True)
                self._stats["failed"] += 1
                raise
            sandbox.touch()
            if self.settings.verify_isolation and self._isolation is None:
                await self._verify_isolation(sandbox)
            return sandbox

    async def _provision(self, scope: Scope, policy: Optional[Policy]) -> Sandbox:
        """Claim a warm container if one fits, otherwise create a fresh one."""
        wanted_image = self.settings.image_for(policy)
        for index, warm in enumerate(self._warm):
            if warm.policy_id == (policy.id if policy else "") and await self._still_running(warm):
                if (await self._image_of(warm)) != wanted_image:
                    continue
                self._warm.pop(index)
                claimed = await self.backend.claim_warm(warm, scope, policy)
                self._stats["claimed_warm"] += 1
                logger.info("handed warm container to %s", scope.describe())
                return claimed
        created = await self.backend.create(scope=scope, policy=policy)
        self._stats["created"] += 1
        logger.info("created sandbox %s for %s", created.name, scope.describe())
        return created

    async def _image_of(self, sandbox: Sandbox) -> str:
        info = await self.backend.docker.inspect_container(sandbox.container_id)
        return ((info or {}).get("Config") or {}).get("Image", "")

    async def _still_running(self, sandbox: Sandbox) -> bool:
        info = await self.backend.docker.inspect_container(sandbox.container_id)
        return bool(info and (info.get("State") or {}).get("Running"))

    async def _wait_ready(self, sandbox: Sandbox) -> None:
        """Poll the container's own health endpoint until it answers.

        The endpoint needs no credential, which is what makes it usable as a
        readiness probe.  A container that exits while we wait is reported with
        the tail of its log, because that is the line that explains why.
        """
        if sandbox.ready:
            return
        deadline = time.monotonic() + self.settings.ready_timeout
        url = f"{sandbox.base_url}/health"
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                response = await self._probe.get(url, timeout=httpx.Timeout(3.0, connect=1.0))
                if response.status_code == 200:
                    sandbox.ready = True
                    logger.info(
                        "sandbox %s ready after %.1fs", sandbox.name,
                        self.settings.ready_timeout - (deadline - time.monotonic()),
                    )
                    return
            except httpx.HTTPError:
                pass
            if attempt % 10 == 0 and not await self._still_running(sandbox):
                break
            await asyncio.sleep(0.25)
        tail = await self.backend.docker.container_logs(sandbox.container_id, tail=25)
        running = await self._still_running(sandbox)
        raise SandboxError(
            f"sandbox {sandbox.name} did not answer on {url} within {self.settings.ready_timeout:.0f}s "
            f"(container {'is still running' if running else 'has exited'})"
            + (f"\n  container log: {tail}" if tail else "")
        )

    # ------------------------------------------------------------------
    # capacity
    # ------------------------------------------------------------------

    @property
    def in_use(self) -> int:
        return len(self._sandboxes) + len(self._warm)

    async def _make_room(self, *, for_warm: bool = False) -> None:
        limit = self.settings.max_sandboxes
        if self.in_use < limit:
            return
        # Warm containers are the first thing to give up: nobody is waiting on them.
        while self._warm and self.in_use >= limit:
            warm = self._warm.pop()
            logger.info("dropping a warm container to make room")
            await self._destroy_quietly(warm)
        if self.in_use < limit:
            return
        if for_warm:
            raise CapacityError()
        evictable = [
            sandbox
            for sandbox in self._sandboxes.values()
            # A sandbox whose lock is held has a request in flight: evicting it
            # would fail that request for no gain.
            if sandbox.idle_seconds >= self.settings.evict_min_idle
            and not self._lock(sandbox.key).locked()
        ]
        if not evictable:
            self._stats["refused"] += 1
            logger.warning(
                "at the ceiling of %d sandboxes and all of them are active: refusing the request", limit
            )
            raise CapacityError(retry_after=max(10, int(self.settings.evict_min_idle)))
        victim = max(evictable, key=lambda item: item.idle_seconds)
        logger.info(
            "evicting %s (idle %.0fs) to make room", victim.name, victim.idle_seconds
        )
        self._stats["evicted"] += 1
        await self._forget(victim, destroy=True)

    # ------------------------------------------------------------------
    # removal
    # ------------------------------------------------------------------

    async def _forget(self, sandbox: Sandbox, *, destroy: bool) -> None:
        # The lock stays: a waiter already holds this object, and replacing it
        # would let two requests provision the same scope at once.  Unused locks
        # are swept below.
        self._sandboxes.pop(sandbox.key, None)
        if destroy:
            await self._destroy_quietly(sandbox)

    async def _destroy_quietly(self, sandbox: Sandbox) -> None:
        # Removal happens on paths that must not fail: eviction, reaping,
        # shutdown.  A daemon that has gone away is logged, not raised.
        try:
            await self.backend.destroy(sandbox)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not remove %s: %s", sandbox.name, exc)

    async def release(self, key: str) -> bool:
        """Remove one sandbox by key.  Used by the admin API."""
        async with self._lock(key):
            sandbox = self._sandboxes.get(key)
            if sandbox is None:
                return False
            await self._forget(sandbox, destroy=True)
            return True

    # ------------------------------------------------------------------
    # background work
    # ------------------------------------------------------------------

    async def _reaper_loop(self) -> None:
        while not self._closing:
            try:
                await asyncio.sleep(self.settings.reap_interval)
                await self._reap_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- a sweep must never kill the loop
                logger.exception("reaper sweep failed: %s", exc)

    async def _reap_once(self) -> None:
        now = time.time()
        for sandbox in list(self._sandboxes.values()):
            idle_limit = self.settings.idle_timeout_for(self.settings.policy(sandbox.policy_id))
            reason = ""
            if now - sandbox.last_used >= idle_limit:
                reason = f"idle for {now - sandbox.last_used:.0f}s"
            elif self.settings.max_lifetime and sandbox.age_seconds >= self.settings.max_lifetime:
                reason = f"reached its maximum lifetime of {self.settings.max_lifetime:.0f}s"
            elif not await self._still_running(sandbox):
                reason = "container is gone"
            if reason:
                logger.info("removing sandbox %s: %s", sandbox.name, reason)
                self._stats["reaped"] += 1
                await self._forget(sandbox, destroy=True)
        for key, lock in list(self._locks.items()):
            if key not in self._sandboxes and not lock.locked():
                self._locks.pop(key, None)
        keep_networks = [sandbox.network for sandbox in self._sandboxes.values()]
        keep_volumes = [
            f"{self.settings.name_prefix}-v-{sandbox.key}" for sandbox in self._sandboxes.values()
        ]
        if self.settings.network_mode == "per-user":
            await self.backend.prune_networks(keep_networks)
        await self.backend.prune_volumes(keep_volumes)

    async def _pool_loop(self) -> None:
        """Keep OTPROXY_POOL_SIZE containers started but unassigned.

        A warm container runs with no network at all until it is claimed, which
        is both cheap and means an unclaimed container cannot talk to anything.
        """
        first_pass = True
        while not self._closing:
            try:
                await asyncio.sleep(0.25 if first_pass else self.settings.reap_interval)
                first_pass = False
                if self._closing:
                    return
                self._warm = [warm for warm in self._warm if await self._still_running(warm)]
                while len(self._warm) < self.settings.pool_size and not self._closing:
                    async with self._global_lock:
                        if self.in_use >= self.settings.max_sandboxes:
                            break
                        warm = await self.backend.create(scope=None, policy=None, role=ROLE_WARM, network="none")
                        self._warm.append(warm)
                        logger.info("warm container %s started (pool %d/%d)",
                                    warm.name, len(self._warm), self.settings.pool_size)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not top up the warm pool: %s", exc)
                await asyncio.sleep(30.0)

    # ------------------------------------------------------------------
    # introspection: what Open WebUI asks for without a user
    # ------------------------------------------------------------------

    #: Everything Open WebUI reads without a user attached.  They describe the
    #: image, not a person, so one container answers all of them once.
    INTROSPECTION_PATHS = ("/openapi.json", "/api/config", "/system")

    async def cached_get(self, path: str) -> Tuple[int, bytes, str]:
        """Serve *path* from a cache, filling it from any sandbox when cold.

        Open WebUI reads ``/openapi.json`` to build its tool definitions, and
        ``/api/config`` and ``/system`` with a three-second timeout -- all
        without an ``X-User-Id``, because they are properties of the image.
        Answering them from a cache keeps a container start off that path, and
        filling the whole set from one container keeps it to one start.
        """
        cached = self._cached(path)
        if cached is not None:
            return cached

        async with self._cache_lock:
            cached = self._cached(path)           # another request may have filled it
            if cached is not None:
                return cached
            sandbox, temporary = await self._introspection_sandbox()
            try:
                wanted = list(self.INTROSPECTION_PATHS)
                if path not in wanted:
                    wanted.append(path)
                for candidate in wanted:
                    result = await self._fetch(sandbox, candidate)
                    if result[0] < 400:
                        self._schema_cache[candidate] = (time.time(), result)
                    elif candidate == path:
                        return result             # pass the sandbox's own error on
            finally:
                if temporary:
                    await self._destroy_quietly(sandbox)
        cached = self._cached(path)
        if cached is None:                        # cached nothing: report it as such
            raise SandboxError(f"the sandbox did not answer {path}")
        return cached

    def _cached(self, path: str) -> Optional[Tuple[int, bytes, str]]:
        entry = self._schema_cache.get(path)
        if entry is None:
            return None
        stored_at, result = entry
        if self.settings.schema_ttl > 0 and time.time() - stored_at >= self.settings.schema_ttl:
            return None
        return result

    async def _fetch(self, sandbox: Sandbox, path: str) -> Tuple[int, bytes, str]:
        response = await self._probe.get(
            f"{sandbox.base_url}{path}",
            headers={"Authorization": f"Bearer {sandbox.api_key}"},
            timeout=httpx.Timeout(20.0, connect=2.0),
        )
        return (
            response.status_code,
            response.content,
            response.headers.get("content-type", "application/json"),
        )

    async def _introspection_sandbox(self) -> Tuple[Sandbox, bool]:
        """Prefer a sandbox that already exists; start a throwaway if none does."""
        for sandbox in self._sandboxes.values():
            if sandbox.ready:
                return sandbox, False
        async with self._global_lock:
            await self._make_room()
            sandbox = await self.backend.create(scope=Scope("otproxy-introspection"), policy=None)
        try:
            await self._wait_ready(sandbox)
        except Exception:
            await self._destroy_quietly(sandbox)
            raise
        return sandbox, True

    # ------------------------------------------------------------------
    # self-check
    # ------------------------------------------------------------------

    async def _verify_isolation(self, sandbox: Sandbox) -> IsolationReport:
        """Measure, from inside a sandbox, what it can still reach.

        Two questions, because Docker only answers the first one by itself:
        can it reach the internet (no -- an internal network has no route), and
        can it reach the host (yes, unless the host drops it: the bridge gateway
        is an address *on the host*, and traffic to it is not forwarded traffic,
        so Docker's own isolation rules never see it).
        """
        report = IsolationReport()
        gateway = await self.backend.network_gateway(sandbox.network)
        script = (
            "import socket\n"
            "def probe(host, port):\n"
            "    s = socket.socket(); s.settimeout(2)\n"
            "    try:\n"
            "        s.connect((host, port)); return 'open'\n"
            "    except Exception as exc:\n"
            "        return type(exc).__name__\n"
            "    finally:\n"
            "        s.close()\n"
            "print('internet', probe('1.1.1.1', 443))\n"
            + (f"print('host', probe({gateway!r}, {self.settings.port}))\n" if gateway else "print('host skipped')\n")
        )
        try:
            result = await self.backend.docker.exec_run(
                sandbox.container_id, ["python3", "-c", script], timeout=20.0
            )
        except (DockerError, SandboxError) as exc:
            report.detail = f"probe could not run: {exc}"
            logger.warning("isolation self-check could not run: %s", exc)
            self._isolation = report
            return report

        report.detail = result.output.strip()
        if result.exit_code != 0:
            report.detail = f"exit {result.exit_code}: {report.detail}"
        for line in result.output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            target, outcome = parts[0], parts[1]
            # A refused connection still means the packet arrived: the host is
            # reachable, just not on that port.  Only an unreachable network or
            # a timeout counts as isolated.
            blocked = outcome in ("OSError", "timeout", "TimeoutError", "socket.timeout")
            if target == "internet":
                report.internet = "blocked" if blocked else "reachable"
            elif target == "host":
                report.host = "blocked" if blocked else "reachable"

        # Three outcomes, and they must not be confused: blocked (good),
        # reachable (a hole), and unknown (the probe itself did not run -- for
        # instance an image without python3).  Claiming a hole on "unknown"
        # would train operators to ignore the line.
        if report.internet_blocked:
            logger.info("isolation self-check: no route to the internet, as intended")
        elif report.internet == "reachable":
            logger.error(
                "ISOLATION: a sandbox reached the internet (%s). The sandbox network is not internal -- "
                "remove it and let the proxy recreate it.", report.detail,
            )
        else:
            logger.warning(
                "isolation self-check could not be completed: %s. It needs python3 in the sandbox image "
                "(the official Open Terminal images have it); set OTPROXY_VERIFY_ISOLATION=false to stop "
                "trying, and check it by hand.", report.detail or "no usable output",
            )
        if report.host == "reachable":
            logger.error(
                "ISOLATION: a sandbox reached the host at %s:%d (%s). Docker cannot block this for you: "
                "run scripts/sandbox-host-firewall.sh install %s on the host, or keep host services "
                "off 0.0.0.0.", gateway, self.settings.port, report.detail, self.settings.supernet,
            )
        self._isolation = report
        if self.settings.require_isolation and not report.ok:
            raise SandboxError(
                "OTPROXY_REQUIRE_ISOLATION is set and the isolation self-check failed: "
                f"internet={report.internet} host={report.host}. {report.detail}"
            )
        return report

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        pool = SubnetPool(self.settings.supernet, self.settings.net_prefix)
        return {
            "sandboxes": len(self._sandboxes),
            "warm": len(self._warm),
            "limit": self.settings.max_sandboxes,
            "network_capacity": pool.capacity,
            "image": self.settings.image,
            "idle_timeout": self.settings.idle_timeout,
            "max_lifetime": self.settings.max_lifetime,
            "isolation": {
                "internet": self._isolation.internet if self._isolation else "unchecked",
                "host": self._isolation.host if self._isolation else "unchecked",
            },
            "counters": dict(self._stats),
        }

    def listing(self) -> List[Dict[str, Any]]:
        return [sandbox.public() for sandbox in sorted(
            self._sandboxes.values(), key=lambda item: item.last_used, reverse=True
        )]

    def metrics(self) -> str:
        """Prometheus text format, with only what is worth alerting on."""
        lines = [
            "# HELP otproxy_sandboxes Sandboxes currently running.",
            "# TYPE otproxy_sandboxes gauge",
            f"otproxy_sandboxes {len(self._sandboxes)}",
            "# HELP otproxy_warm_containers Pre-started containers not yet assigned.",
            "# TYPE otproxy_warm_containers gauge",
            f"otproxy_warm_containers {len(self._warm)}",
            "# HELP otproxy_sandbox_limit Configured ceiling.",
            "# TYPE otproxy_sandbox_limit gauge",
            f"otproxy_sandbox_limit {self.settings.max_sandboxes}",
        ]
        for name, value in self._stats.items():
            lines += [
                f"# HELP otproxy_{name}_total Sandboxes {name} since start.",
                f"# TYPE otproxy_{name}_total counter",
                f"otproxy_{name}_total {value}",
            ]
        isolation = self._isolation
        lines += [
            "# HELP otproxy_isolation_ok 1 when the last self-check found no route out of a sandbox.",
            "# TYPE otproxy_isolation_ok gauge",
            f"otproxy_isolation_ok {1 if (isolation and isolation.ok) else 0}",
        ]
        return "\n".join(lines) + "\n"
