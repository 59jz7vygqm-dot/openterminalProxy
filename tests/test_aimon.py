"""Checks for the aimonitor reporting: payload, buffer, backoff, and silence.

Driven against a stub that speaks the documented interface and can also
misbehave on purpose -- answer 400, answer 429 with Retry-After, or simply not
answer.  The point of most of these checks is the first requirement of the
brief: whatever the monitoring does, the proxy's own work must not get slower
or less reliable.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import httpx

from fakes import FakeBackend, FakeTerminal, Server
from otproxy import config
from otproxy.aimon import AimonConfig, HostSampler, NoTelemetry, Telemetry, example_snapshot, self_test
from otproxy.ids import Scope
from otproxy.manager import SandboxManager

KEY = "0123456789abcdef-proxy"
PASSED = 0
FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  ok   {name}")
    else:
        FAILED += 1
        print(f"  FAIL {name}{' -- ' + detail if detail else ''}")


# ----------------------------------------------------------------------
# a stub aimonitor
# ----------------------------------------------------------------------


class AimonStub:
    """Answers /api/v1/ingest/scaler, and misbehaves when told to."""

    def __init__(self) -> None:
        self.batches: List[Dict[str, Any]] = []
        self.paths: List[str] = []
        self.auth: List[str] = []
        self.status = 202
        self.retry_after: Optional[str] = None
        self.hang = 0.0

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        headers = {key.decode(): value.decode() for key, value in scope["headers"]}
        self.auth.append(headers.get("authorization", ""))
        query = scope["query_string"].decode()
        self.paths.append(scope["path"] + (f"?{query}" if query else ""))
        if self.hang:
            await asyncio.sleep(self.hang)
        if self.status == 202:
            try:
                batch = json.loads(body)
            except ValueError:
                batch = {"unparseable": body.decode("utf-8", "replace")}
            self.batches.append(batch)
            accepted = 1 + len(batch.get("instances") or []) + len(batch.get("events") or [])
            payload = json.dumps({"accepted": accepted, "rejected": 0, "errors": []}).encode()
        else:
            payload = json.dumps({"accepted": 0, "rejected": 1, "errors": ["stub"]}).encode()
        response_headers = [(b"content-type", b"application/json")]
        if self.retry_after:
            response_headers.append((b"retry-after", self.retry_after.encode()))
        await send({"type": "http.response.start", "status": self.status, "headers": response_headers})
        await send({"type": "http.response.body", "body": payload})


class Recorder:
    """Stands in for asyncio.sleep so waits are asserted, not served."""

    def __init__(self) -> None:
        self.delays: List[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def settings_for(**extra: str) -> config.Settings:
    return config.load({"OTPROXY_API_KEY": KEY, "OTPROXY_POOL_SIZE": "0", **extra})


def telemetry_for(stub_port: int, **extra: Any) -> Telemetry:
    cfg = AimonConfig(
        url=f"http://127.0.0.1:{stub_port}",
        token="aimon-token",
        node="proxy-host-01",
        service_key="openterminal-proxy@proxy-host-01:8800",
        version="1.0.0",
        interval=extra.pop("interval", 10.0),
        timeout=extra.pop("timeout", 5.0),
        buffer_seconds=extra.pop("buffer_seconds", 600.0),
    )
    return Telemetry(cfg, **extra)


# ----------------------------------------------------------------------
# configuration
# ----------------------------------------------------------------------


def test_config() -> None:
    print("\nconfiguration")
    saved = {name: os.environ.pop(name) for name in list(os.environ) if name.startswith("AIMON_")}
    try:
        check("without AIMON_URL the whole thing is off", not AimonConfig.from_env().enabled)
        os.environ["AIMON_URL"] = "http://aimon.lan:8420/"
        os.environ["AIMON_NODE"] = "proxy-host-01"
        cfg = AimonConfig.from_env(8800, "1.0.0")
        check("the endpoint is the documented path",
              cfg.endpoint == "http://aimon.lan:8420/api/v1/ingest/scaler", cfg.endpoint)
        check("the service key defaults to node and port",
              cfg.service_key == "openterminal-proxy@proxy-host-01:8800", cfg.service_key)
        check("ten minutes of buffer at ten seconds is sixty batches", cfg.buffered_batches == 60)
        os.environ["AIMON_INTERVAL"] = "30"
        check("a longer interval means fewer batches for the same ten minutes",
              AimonConfig.from_env().buffered_batches == 20)
        os.environ["AIMON_INTERVAL"] = "nonsense"
        check("an unreadable interval falls back instead of failing",
              AimonConfig.from_env().interval == 10.0)
    finally:
        for name in list(os.environ):
            if name.startswith("AIMON_"):
                del os.environ[name]
        os.environ.update(saved)


def test_host_sampler() -> None:
    print("\nhost measurement")
    sampler = HostSampler()
    first = sampler.sample()
    check("the first sample has no cpu, it only sets the baseline", "cpu_pct" not in first)
    check("memory is read straight away", "mem_total_bytes" in first and first["mem_total_bytes"] > 0)
    time.sleep(0.15)
    second = sampler.sample()
    check("the second sample has a cpu reading", "cpu_pct" in second, str(second))
    check("and it is a percentage", 0.0 <= second.get("cpu_pct", -1) <= 100.0, str(second))
    check("used is below total",
          second["mem_used_bytes"] < second["mem_total_bytes"], str(second))


# ----------------------------------------------------------------------
# the payload
# ----------------------------------------------------------------------


async def test_payload() -> None:
    print("\nthe payload")
    telemetry = telemetry_for(1, client=None)
    telemetry._snapshot = lambda: {
        "state": {"instances_running": 3, "instances_max": 14, "sessions_per_instance_target": 1},
        "instances": [{"id": "abc123", "state": "running", "sessions": 1, "started_at": 1}],
    }
    telemetry.event("scale.up", "Scale up: 2 -> 3 sandboxes", reason="demand", detail={"from": 2, "to": 3})
    batch = telemetry.build_batch()

    check("node and service are always there",
          batch["node"]["name"] == "proxy-host-01" and batch["service"]["key"].startswith("openterminal-proxy@"))
    check("the service says what kind of thing it is", batch["service"]["kind"] == "openterminal_proxy")
    check("the timestamp is unix seconds", isinstance(batch["ts"], int) and batch["ts"] > 1_700_000_000)
    check("the state is passed through", batch["state"]["instances_running"] == 3)
    check("the host measurement is merged in", "mem_total_bytes" in batch["state"])
    check("the last reason travels with the state", batch["state"]["last_scale_reason"] == "demand")
    check("the event is in the batch", batch["events"][0]["kind"] == "scale.up")
    check("an event carries the service it belongs to",
          batch["events"][0]["service"] == "openterminal-proxy@proxy-host-01:8800")

    text = json.dumps(batch)
    for computed in ("headroom", "saturation", "capacity_sessions"):
        check(f"{computed} is not computed here", computed not in text,
              "aimonitor derives it; two places would drift apart")

    again = telemetry.build_batch()
    check("events are sent once, not again in the next batch", "events" not in again)

    empty = Telemetry(AimonConfig(url="http://x", node="n", service_key="k"))
    bare = empty.build_batch()
    check("without a snapshot only the required fields are sent",
          set(bare) <= {"node", "service", "ts", "state"}, str(sorted(bare)))

    telemetry.event("scale.sideways", "nonsense")
    check("an unknown event kind is dropped, not sent", not telemetry._events)


async def test_snapshot_mapping() -> None:
    print("\nwhat the numbers mean")
    terminal = FakeTerminal()
    upstream = Server(terminal).start()
    try:
        settings = settings_for(OTPROXY_MAX_SANDBOXES="14", OTPROXY_POOL_SIZE="0")
        manager = SandboxManager(settings, FakeBackend(settings, upstream.port))
        await manager.start()
        try:
            await manager.acquire(Scope("alice-5f3a-uuid"))
            await manager.acquire(Scope("bob-9c21-uuid"))
            snapshot = manager.telemetry_snapshot()
            state = snapshot["state"]
            check("two users serving means two instances running", state["instances_running"] == 2)
            check("and two sessions active", state["sessions_active"] == 2)
            check("one user per container is the target", state["sessions_per_instance_target"] == 1)
            check("the ceiling is the configured one", state["instances_max"] == 14)
            check("nothing is queued, the proxy refuses instead", state["sessions_queued"] == 0)
            check("nothing drains", state["instances_draining"] == 0)
            check("no cooldown exists", state["scale_cooldown_s_remaining"] == 0)
            check("two instances are listed", len(snapshot["instances"]) == 2)
            check("an instance is identified by container id, not by name",
                  all(len(item["id"]) <= 12 for item in snapshot["instances"]))

            # A sandbox that is not ready yet counts as starting, not running.
            manager._sandboxes[list(manager._sandboxes)[0]].ready = False
            state = manager.telemetry_snapshot()["state"]
            check("a sandbox still starting is not counted as running",
                  state["instances_running"] == 1 and state["instances_starting"] == 1)
            check("but it is still wanted", state["instances_desired"] == 2)

            text = json.dumps(manager.telemetry_snapshot())
            for secret in ("alice", "bob", "uuid"):
                check(f"no user reference in the payload ({secret})", secret not in text)
        finally:
            for task in manager._tasks:
                task.cancel()
            await manager.close()
    finally:
        upstream.stop()


# ----------------------------------------------------------------------
# sending
# ----------------------------------------------------------------------


async def test_sending() -> None:
    print("\nsending, and what happens when it fails")
    stub = AimonStub()
    server = Server(stub).start()
    try:
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
            sleeps = Recorder()
            telemetry = telemetry_for(server.port, client=client, sleep=sleeps)
            telemetry._snapshot = lambda: {"state": {"instances_running": 1}, "instances": []}

            await telemetry._tick()
            check("a batch is accepted and leaves the buffer", telemetry.stats()["buffered_batches"] == 0)
            check("the token is sent as a bearer", stub.auth[-1] == "Bearer aimon-token")
            check("it goes to the documented path", stub.paths[-1] == "/api/v1/ingest/scaler")
            check("the server saw the state", stub.batches[-1]["state"]["instances_running"] == 1)

            stub.status = 500
            await telemetry._tick()
            check("a server error keeps the batch for later", telemetry.stats()["buffered_batches"] == 1)
            check("and waits before trying again", len(sleeps.delays) == 1)
            check("the first wait is about a second", 0.8 <= sleeps.delays[0] <= 1.2, str(sleeps.delays))

            await telemetry._tick()
            await telemetry._tick()
            check("failures stack up in the buffer", telemetry.stats()["buffered_batches"] == 3)
            check("the waits grow", sleeps.delays[-1] > sleeps.delays[0], str(sleeps.delays))

            stub.status = 202
            await telemetry.flush()
            check("when it comes back everything buffered is delivered",
                  telemetry.stats()["buffered_batches"] == 0)

            stub.status = 429
            stub.retry_after = "7"
            sleeps.delays.clear()
            await telemetry._tick()
            check("a 429 is not a reason to drop the batch", telemetry.stats()["buffered_batches"] == 1)
            check("Retry-After is honoured exactly", sleeps.delays == [7.0], str(sleeps.delays))

            stub.status, stub.retry_after = 400, None
            errors: List[str] = []
            telemetry._pending.clear()
            import otproxy.aimon as aimon_module

            original = aimon_module.logger.error
            aimon_module.logger.error = lambda *args, **kwargs: errors.append(str(args[0]))
            try:
                await telemetry._tick()
                await telemetry._tick()
            finally:
                aimon_module.logger.error = original
            check("a 400 is dropped rather than retried", telemetry.stats()["buffered_batches"] == 0)
            check("and complained about once, not every cycle", len(errors) == 1, str(errors))
    finally:
        server.stop()


async def test_backoff_and_buffer() -> None:
    print("\nbackoff and buffer bounds")
    telemetry = telemetry_for(1, buffer_seconds=60.0, interval=10.0)
    check("the buffer holds about ten minutes' worth, not more",
          telemetry.config.buffered_batches == 6)
    telemetry._snapshot = lambda: {"state": {"instances_running": 0}}
    for _ in range(20):
        telemetry._pending.append(telemetry.build_batch())
    check("an overflowing buffer drops the oldest, it does not grow",
          len(telemetry._pending) == 6)

    delays = [telemetry.backoff_delay(attempt) for attempt in range(1, 9)]
    check("the first wait is near a second", 0.8 <= delays[0] <= 1.2, str(delays[0]))
    check("it doubles", 1.6 <= delays[1] <= 2.4 and 3.2 <= delays[2] <= 4.8, str(delays[:3]))
    check("and stops at a minute", all(delay <= 72.0 for delay in delays) and delays[-1] >= 48.0,
          str(delays[-1]))
    check("there is jitter, not a lockstep", len({round(telemetry.backoff_delay(4), 6) for _ in range(5)}) > 1)

    queue = Telemetry(AimonConfig(url="http://x", node="n", service_key="k"))
    for index in range(5000):
        queue.event("scale.up", f"event {index}")
    check("the event queue is bounded too", len(queue._events) <= 2048)


async def test_never_blocks() -> None:
    print("\nnever in the way of the data path"
          )
    stub = AimonStub()
    stub.hang = 3.0
    server = Server(stub).start()
    terminal = FakeTerminal()
    upstream = Server(terminal).start()
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            settings = settings_for()
            manager = SandboxManager(settings, FakeBackend(settings, upstream.port))
            telemetry = telemetry_for(server.port, client=client)
            telemetry._snapshot = manager.telemetry_snapshot
            manager.telemetry = telemetry
            await manager.start()
            try:
                hanging = asyncio.create_task(telemetry._tick())
                await asyncio.sleep(0.1)
                started = time.monotonic()
                await manager.acquire(Scope("user-while-monitoring-hangs"))
                for index in range(200):
                    manager.telemetry.event("scale.up", f"burst {index}")
                elapsed = time.monotonic() - started
                check("a sandbox is served while the monitoring hangs", elapsed < 1.0,
                      f"took {elapsed:.2f}s")
                check("and the hanging request is still in flight", not hanging.done())
                hanging.cancel()
                try:
                    await hanging
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            finally:
                for task in manager._tasks:
                    task.cancel()
                await manager.close()
    finally:
        upstream.stop()
        server.stop()


async def test_events_from_the_manager() -> None:
    print("\nthe events the proxy actually reports")
    terminal = FakeTerminal()
    upstream = Server(terminal).start()
    try:
        settings = settings_for(OTPROXY_MAX_SANDBOXES="1", OTPROXY_EVICT_MIN_IDLE="3600")
        manager = SandboxManager(settings, FakeBackend(settings, upstream.port))
        telemetry = telemetry_for(1)            # never started: we read its queue
        manager.telemetry = telemetry
        await manager.start()
        try:
            await manager.acquire(Scope("u1"))
            kinds = [event["kind"] for event in telemetry._events]
            check("starting a sandbox is a scale up", kinds == ["scale.up"], str(kinds))
            check("with from and to", telemetry._events[0]["detail"]["to"] == 1)

            telemetry._events.clear()
            from otproxy.manager import CapacityError

            refused = False
            try:
                await manager.acquire(Scope("u2"))
            except CapacityError:
                refused = True
            check("a refusal happened at the ceiling", refused)
            blocked = [event for event in telemetry._events if event["kind"] == "scale.blocked"]
            check("and it is reported as scale.blocked", len(blocked) == 1, str(telemetry._events))
            check("as a warning", blocked and blocked[0]["severity"] == "warning")
            check("with a dedup key, so an overload does not flood the log",
                  blocked and blocked[0]["dedup_key"] == "scale.blocked:max")
            check("naming what blocked it", blocked and blocked[0]["detail"]["blocked_by"] == "max")

            telemetry._events.clear()
            sandbox = list(manager._sandboxes.values())[0]
            sandbox.last_used = time.time() - 10_000
            await manager._reap_once()
            downs = [event for event in telemetry._events if event["kind"] == "scale.down"]
            check("reaping an idle sandbox is a scale down", len(downs) == 1, str(telemetry._events))
            check("with the reason it went", "idle" in downs[0]["detail"]["reason"], str(downs[0]))

            telemetry._events.clear()
            await manager.acquire(Scope("u3"))
            dead = list(manager._sandboxes.values())[0]
            await manager.invalidate(dead)
            unhealthy = [event for event in telemetry._events if event["kind"] == "instance.unhealthy"]
            check("a sandbox that stopped answering is reported", len(unhealthy) == 1, str(telemetry._events))

            telemetry._events.clear()
            from otproxy.sandbox import SandboxError

            manager.backend.fail_next_create = SandboxError("image is missing")
            try:
                await manager.acquire(Scope("u4"))
            except SandboxError:
                pass
            failed = [event for event in telemetry._events if event["kind"] == "scale.failed"]
            check("a failed start is reported as an error",
                  len(failed) == 1 and failed[0]["severity"] == "error", str(telemetry._events))
            check("with an error class, not a stacktrace",
                  failed and failed[0]["detail"]["error"] == "create_failed", str(failed))
            check("and no traceback in it", failed and "Traceback" not in json.dumps(failed[0]))
        finally:
            for task in manager._tasks:
                task.cancel()
            await manager.close()
    finally:
        upstream.stop()


async def test_self_test() -> None:
    print("\nthe self-test from section 5")
    stub = AimonStub()
    server = Server(stub).start()
    try:
        cfg = AimonConfig(url=f"http://127.0.0.1:{server.port}", token="t", node="proxy-host-01",
                          service_key="openterminal-proxy@proxy-host-01:8800")
        status, body = await self_test(cfg, example_snapshot(14, 1))
        check("the self-test gets a 202", status == 202, f"{status} {body}")
        check("and the server's answer is passed back", json.loads(body)["accepted"] >= 1, body)
        sent = stub.batches[-1]
        check("it sends the real ceiling", sent["state"]["instances_max"] == 14)
        check("and marks itself as a self-test", sent["events"][0]["detail"]["self_test"] is True)

        status, _ = await self_test(cfg, example_snapshot(14, 1), dry_run=True)
        check("dry_run is passed to the server", stub.paths[-1].endswith("?dry_run=1"), stub.paths[-1])

        # The command the brief asks for, run as the operator would.
        environment = {
            **os.environ,
            "OTPROXY_API_KEY": KEY,
            "AIMON_URL": f"http://127.0.0.1:{server.port}",
            "AIMON_NODE": "proxy-host-01",
            "OTPROXY_MAX_SANDBOXES": "14",
        }
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                [sys.executable, "-m", "otproxy", "--aimon-test"],
                cwd=os.path.join(os.path.dirname(__file__), ".."),
                capture_output=True, text=True, env=environment, timeout=60,
            ),
        )
        check("python -m otproxy --aimon-test exits cleanly", result.returncode == 0,
              result.stdout + result.stderr)
        check("and prints the line the brief asks for",
              result.stdout.startswith(f"POST http://127.0.0.1:{server.port}/api/v1/ingest/scaler -> 202"),
              result.stdout.strip())
    finally:
        server.stop()


async def test_disabled() -> None:
    print("\nswitched off")
    nothing = NoTelemetry()
    nothing.event("scale.up", "nobody sees this")
    await nothing.start()
    await nothing.close()
    check("the no-op reporter does nothing and says so", nothing.stats() == {"enabled": False})

    terminal = FakeTerminal()
    upstream = Server(terminal).start()
    try:
        settings = settings_for()
        manager = SandboxManager(settings, FakeBackend(settings, upstream.port))
        await manager.start()
        try:
            await manager.acquire(Scope("u1"))
            check("a proxy without AIMON_URL serves normally", manager.in_use == 1)
            check("and reports nothing", manager.status()["telemetry"] == {"enabled": False})
        finally:
            for task in manager._tasks:
                task.cancel()
            await manager.close()
    finally:
        upstream.stop()


async def test_broken_telemetry_cannot_stop_the_proxy() -> None:
    print("\na broken monitoring must not take the proxy with it")
    import otproxy.aimon as aimon_module
    from otproxy.app import create_app

    terminal = FakeTerminal()
    upstream = Server(terminal).start()
    original = aimon_module.Telemetry.start

    async def explode(self) -> None:
        raise RuntimeError("aimonitor client refuses to be created")

    aimon_module.Telemetry.start = explode
    os.environ["AIMON_URL"] = "http://127.0.0.1:1"
    os.environ["AIMON_NODE"] = "proxy-host-01"
    try:
        settings = settings_for()
        manager = SandboxManager(settings, FakeBackend(settings, upstream.port))
        server = Server(create_app(settings, manager)).start()
        try:
            async with httpx.AsyncClient(base_url=server.base, timeout=30.0, trust_env=False) as client:
                response = await client.get("/health")
                check("the proxy starts anyway", response.status_code == 200, response.text[:120])
                response = await client.post(
                    "/execute", json={"command": "x"},
                    headers={"Authorization": f"Bearer {KEY}", "X-User-Id": "u1"},
                )
                check("and serves normally", response.status_code == 200, response.text[:160])
                check("with telemetry switched off", manager.telemetry.stats() == {"enabled": False})
        finally:
            server.stop()
    finally:
        aimon_module.Telemetry.start = original
        os.environ.pop("AIMON_URL", None)
        os.environ.pop("AIMON_NODE", None)
        upstream.stop()


async def main() -> int:
    test_config()
    test_host_sampler()
    await test_payload()
    await test_snapshot_mapping()
    await test_sending()
    await test_backoff_and_buffer()
    await test_never_blocks()
    await test_events_from_the_manager()
    await test_self_test()
    await test_disabled()
    await test_broken_telemetry_cannot_stop_the_proxy()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
