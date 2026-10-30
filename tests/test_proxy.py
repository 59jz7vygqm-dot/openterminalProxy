"""End-to-end checks of the proxy itself, with a fake Open Terminal behind it.

The real FastAPI app runs under uvicorn on loopback and is driven with a real
HTTP and WebSocket client, so what is exercised here is the actual request path:
authentication, the key swap, routing by user, streaming, the lifecycle rules
and the admin API.  Only Docker is faked -- tests/test_docker.py covers that.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import httpx
import websockets

from fakes import UPSTREAM_KEY, FakeBackend, FakeTerminal, Server
from otproxy import config
from otproxy.app import create_app
from otproxy.manager import SandboxManager

KEY = "0123456789abcdef-proxy"
ADMIN = "0123456789abcdef-admin"
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


class Harness:
    """One proxy, one fake sandbox server, for the duration of a `with` block."""

    def __init__(self, **environment: str) -> None:
        self.terminal = FakeTerminal()
        self.upstream = Server(self.terminal)
        self.environment = {"OTPROXY_API_KEY": KEY, "OTPROXY_POOL_SIZE": "0", **environment}

    async def __aenter__(self) -> "Harness":
        self.upstream.start()
        self.settings = config.load(dict(self.environment))
        self.backend = FakeBackend(self.settings, self.upstream.port)
        self.manager = SandboxManager(self.settings, self.backend)
        self.server = Server(create_app(self.settings, self.manager))
        self.server.start()
        self.client = httpx.AsyncClient(base_url=self.server.base, timeout=30.0, trust_env=False)
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()
        self.server.stop()
        self.upstream.stop()

    # convenience ----------------------------------------------------
    def auth(self, user: str = "user-a", **extra: str) -> dict:
        headers = {"Authorization": f"Bearer {KEY}", "X-User-Id": user}
        headers.update(extra)
        return headers


async def test_public_endpoints(h: Harness) -> None:
    print("\nendpoints that must answer without starting a container")
    response = await h.client.get("/health")
    check("/health answers without a key", response.status_code == 200 and response.json()["status"] == "ok")
    check("/health starts nothing", not h.backend.created, f"{len(h.backend.created)} containers")

    response = await h.client.get("/openapi.json")
    check("/openapi.json is served", response.status_code == 200 and "paths" in response.json())
    first = response.json()
    check("the schema came from a container", len(h.backend.created) == 1)
    check("the throwaway container was removed again", len(h.backend.destroyed) == 1)
    response = await h.client.get("/openapi.json")
    check("the schema is cached", response.json() == first and len(h.backend.created) == 1)

    response = await h.client.get("/api/config")
    check("/api/config is served from the image", response.json()["features"]["system"] is True)
    check("/api/config did not start another container", len(h.backend.created) == 1)

    response = await h.client.get("/system", headers={"Authorization": f"Bearer {KEY}"})
    check("/system without a user is cached too", response.status_code == 200
          and "prompt" in response.json() and len(h.backend.created) == 1)

    # Open WebUI reads a policy's prompt as the literal user "system"; starting a
    # container for it would be a container nobody ever works in.
    response = await h.client.get("/system", headers={"Authorization": f"Bearer {KEY}", "X-User-Id": "system"})
    check("the 'system' user does not get a container of its own",
          response.status_code == 200 and len(h.backend.created) == 1)
    check("/system still needs a key", (await h.client.get("/system")).status_code == 401)


async def test_authentication(h: Harness) -> None:
    print("\nauthentication")
    response = await h.client.post("/execute", json={"command": "id"}, headers={"X-User-Id": "user-a"})
    check("no key is rejected", response.status_code == 401)
    response = await h.client.post(
        "/execute", json={"command": "id"},
        headers={"Authorization": "Bearer wrong-key-wrong-key", "X-User-Id": "user-a"},
    )
    check("a wrong key is rejected", response.status_code == 401)
    check("a rejected request starts nothing", not h.backend.created)

    response = await h.client.post("/execute", json={"command": "id"}, headers={"Authorization": f"Bearer {KEY}"})
    check("a missing X-User-Id is a 400, not a shared sandbox", response.status_code == 400)
    check("the message names the header", "X-User-Id" in response.text)

    response = await h.client.post(
        "/execute", json={"command": "id"},
        headers={"Authorization": f"Bearer {KEY}", "X-User-Id": "user;rm -rf /"},
    )
    check("a hostile user id is refused", response.status_code == 400)


async def test_routing(h: Harness) -> None:
    print("\nrouting and the key swap")
    response = await h.client.post(
        "/execute", json={"command": "whoami"},
        headers=h.auth("user-a", **{"X-Session-Id": "chat-1"}),
    )
    check("a tool call reaches the sandbox", response.status_code == 200, response.text[:200])
    body = response.json()
    check("the command body is forwarded", json.loads(body["echo"])["command"] == "whoami")
    check("the user id is forwarded", body["user"] == "user-a")
    check("the session id is forwarded", body["session"] == "chat-1")
    seen = [item for item in h.terminal.requests if item["path"] == "/execute"][-1]
    check("the container sees its own key, not Open WebUI's",
          seen["headers"]["authorization"] == f"Bearer {UPSTREAM_KEY}")
    check("one container for one user", len(h.backend.created) == 1)

    await h.client.post("/execute", json={"command": "again"}, headers=h.auth("user-a"))
    check("a second call reuses the sandbox", len(h.backend.created) == 1)

    await h.client.post("/execute", json={"command": "hi"}, headers=h.auth("user-b"))
    check("another user gets another sandbox", len(h.backend.created) == 2)

    keys = {sandbox.key for sandbox in h.backend.created}
    check("the two sandboxes have different keys", len(keys) == 2)

    results = await asyncio.gather(*[
        h.client.post("/execute", json={"command": "burst"}, headers=h.auth("user-c")) for _ in range(5)
    ])
    check("a burst of calls produces one container", len(h.backend.created) == 3,
          f"created {len(h.backend.created)}")
    check("every call in the burst succeeded", all(item.status_code == 200 for item in results))

    await h.client.post("/execute", json={"command": "x"},
                        headers=h.auth("user-a", **{"X-Terminal-Context-Id": "chat:42"}))
    check("a terminal context gets its own sandbox", len(h.backend.created) == 4)


async def test_streaming_and_limits(h: Harness) -> None:
    print("\nstreaming and body limits")
    response = await h.client.get("/big?n=1048576", headers=h.auth("user-s"))
    check("a megabyte comes back intact", response.status_code == 200 and len(response.content) == 1048576,
          f"{len(response.content)} bytes")
    check("the content type survives", response.headers["content-type"] == "application/octet-stream")

    response = await h.client.post("/files/upload", content=b"y" * 200_000, headers=h.auth("user-s"))
    check("an upload is streamed through", response.json()["received"] == 200_000)


async def test_body_limit() -> None:
    print("\nbody limit")
    async with Harness(OTPROXY_MAX_BODY="64k") as h:
        response = await h.client.post("/files/upload", content=b"z" * 200_000, headers=h.auth("user-s"))
        check("an oversized body is refused", response.status_code == 413, response.text[:120])
        response = await h.client.post("/files/upload", content=b"z" * 1000, headers=h.auth("user-s"))
        check("a small body still passes", response.json()["received"] == 1000)


async def test_websocket(h: Harness) -> None:
    print("\ninteractive terminal socket")
    url = f"{h.server.ws_base}/api/terminals/sess-1"
    async with websockets.connect(url, additional_headers={"X-User-Id": "user-w"}) as ws:
        await ws.send(json.dumps({"type": "auth", "token": KEY, "chat_id": "chat-9"}))
        hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        check("the socket reaches the right sandbox path", hello["hello"] == "/api/terminals/sess-1")
        check("the user id is forwarded on the socket", hello["user"] == "user-w")
        check("the chat id is forwarded on the socket", hello["chat"] == "chat-9")
        await ws.send(b"ls -la\n")
        echoed = await asyncio.wait_for(ws.recv(), timeout=10)
        check("keystrokes and output are relayed", echoed == b"echo:ls -la\n", repr(echoed))
    check("the container was given its own key on the socket",
          h.terminal.ws_auth_tokens and h.terminal.ws_auth_tokens[-1] == UPSTREAM_KEY)

    async with websockets.connect(url, additional_headers={"X-User-Id": "user-w"}) as ws:
        await ws.send(json.dumps({"type": "auth", "token": "nope"}))
        try:
            await asyncio.wait_for(ws.recv(), timeout=10)
        except websockets.exceptions.ConnectionClosed as exc:
            check("a wrong key closes the socket with 4001", exc.code == 4001, f"code {exc.code}")
        else:
            check("a wrong key closes the socket with 4001", False, "socket stayed open")

    async with websockets.connect(f"{h.server.ws_base}/api/terminals/s2") as ws:
        await ws.send(json.dumps({"type": "auth", "token": KEY}))
        try:
            await asyncio.wait_for(ws.recv(), timeout=10)
        except websockets.exceptions.ConnectionClosed as exc:
            check("a socket without a user id is refused", exc.code == 4003, f"code {exc.code}")
        else:
            check("a socket without a user id is refused", False, "socket stayed open")


async def test_capacity() -> None:
    print("\ncapacity")
    async with Harness(OTPROXY_MAX_SANDBOXES="2", OTPROXY_EVICT_MIN_IDLE="3600") as h:
        for user in ("u1", "u2"):
            response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth(user))
            check(f"{user} gets a sandbox", response.status_code == 200)
        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u3"))
        check("a full host refuses rather than overcommits", response.status_code == 503, response.text[:120])
        check("the refusal tells the caller when to retry", "retry-after" in response.headers)
        check("nothing was evicted while in use", not h.backend.destroyed)

    async with Harness(OTPROXY_MAX_SANDBOXES="2", OTPROXY_EVICT_MIN_IDLE="0") as h:
        for user in ("u1", "u2"):
            await h.client.post("/execute", json={"command": "x"}, headers=h.auth(user))
        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u3"))
        check("with eviction allowed the newcomer gets in", response.status_code == 200)
        check("the longest-idle sandbox was evicted", len(h.backend.destroyed) == 1)
        check("the evicted sandbox was the first one", h.backend.destroyed[0] is h.backend.created[0])

    # A sandbox with a request in flight must not be the one that gets evicted.
    async with Harness(OTPROXY_MAX_SANDBOXES="2", OTPROXY_EVICT_MIN_IDLE="0") as h:
        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u2"))
        busy = h.manager._lock(h.backend.created[0].key)
        await busy.acquire()
        try:
            await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u3"))
            check("a sandbox with a request in flight is not evicted",
                  h.backend.destroyed and h.backend.destroyed[0] is h.backend.created[1])
        finally:
            busy.release()


async def test_reaper() -> None:
    print("\nidle reaping and lifetime")
    async with Harness(OTPROXY_IDLE_TIMEOUT="60", OTPROXY_MAX_LIFETIME="120") as h:
        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        sandbox = h.backend.created[0]
        sandbox.last_used = time.time() - 3600
        await h.manager._reap_once()
        check("an idle sandbox is removed", h.backend.destroyed == [sandbox])
        check("the manager forgot it", h.manager.in_use == 0)

        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u2"))
        fresh = h.backend.created[1]
        fresh.created = time.time() - 10_000
        await h.manager._reap_once()
        check("a sandbox past its maximum lifetime is removed", fresh in h.backend.destroyed)

        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u3"))
        gone = h.backend.created[2]
        h.backend.docker.containers.pop(gone.container_id)
        await h.manager._reap_once()
        check("a sandbox whose container vanished is forgotten", h.manager.in_use == 0)

        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u3"))
        check("the next request starts a fresh one", response.status_code == 200 and len(h.backend.created) == 4)


async def test_admin(h: Harness) -> None:
    print("\nadmin API")
    response = await h.client.get("/api/v1/status")
    check("the admin API is off until a key is set", response.status_code == 404)
    check("the 404 says how to enable it", "OTPROXY_ADMIN_KEY" in response.text)

    async with Harness(OTPROXY_ADMIN_KEY=ADMIN) as admin:
        await admin.client.post("/execute", json={"command": "x"}, headers=admin.auth("u1"))
        response = await admin.client.get("/api/v1/status")
        check("the admin API needs its own key", response.status_code == 401)
        response = await admin.client.get("/api/v1/status", headers={"Authorization": f"Bearer {KEY}"})
        check("the Open WebUI key is not an admin key", response.status_code == 401)

        headers = {"Authorization": f"Bearer {ADMIN}"}
        response = await admin.client.get("/api/v1/status", headers=headers)
        status = response.json()
        check("status reports one sandbox", status["sandboxes"] == 1)
        check("status reports the ceiling", status["limit"] == admin.settings.max_sandboxes)

        response = await admin.client.get("/api/v1/terminals", headers=headers)
        listing = response.json()["terminals"]
        check("the listing names the user", listing[0]["user_id"] == "u1")
        check("the listing carries no key", "api_key" not in json.dumps(listing))

        key = listing[0]["key"]
        response = await admin.client.delete(f"/api/v1/terminals/{key}", headers=headers)
        check("an admin can remove a sandbox", response.status_code == 200 and response.json()["removed"])
        response = await admin.client.delete(f"/api/v1/terminals/{key}", headers=headers)
        check("removing it twice is a 404", response.status_code == 404)

        response = await admin.client.get("/metrics", headers=headers)
        check("metrics are exported", "otproxy_sandboxes" in response.text)
        response = await admin.client.get("/metrics")
        check("metrics need the admin key by default", response.status_code == 401)


async def test_policies() -> None:
    print("\npolicies")
    policies = json.dumps({"ds": {"image": "data-science:1", "memory": "4g"}})
    async with Harness(OTPROXY_POLICIES=policies) as h:
        response = await h.client.post("/p/ds/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("a policy route works", response.status_code == 200, response.text[:160])
        check("the sandbox carries the policy", h.backend.created[0].policy_id == "ds")
        response = await h.client.post("/p/nope/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("an unknown policy is a 404", response.status_code == 404)
        check("the 404 lists what is configured", "ds" in response.text)
        await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("the same user gets a separate sandbox per policy", len(h.backend.created) == 2)


async def test_sandbox_clients_refused() -> None:
    print("\nrequests coming from inside a sandbox")
    # The supernet is pointed at loopback so that this test's own requests look
    # like they come from a sandbox.
    async with Harness(OTPROXY_NET_SUPERNET="127.0.0.0/8") as h:
        response = await h.client.get("/health")
        check("a request from the sandbox range is refused", response.status_code == 403)
        url = f"{h.server.ws_base}/api/terminals/s1"
        async with websockets.connect(url, additional_headers={"X-User-Id": "u1"}) as ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=10)
            except websockets.exceptions.ConnectionClosed as exc:
                check("a socket from the sandbox range is refused", exc.code == 4003, f"code {exc.code}")
            else:
                check("a socket from the sandbox range is refused", False, "socket stayed open")


async def test_warm_pool() -> None:
    print("\nwarm pool")
    async with Harness(OTPROXY_POOL_SIZE="1", OTPROXY_REAP_INTERVAL="1") as h:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not h.manager._warm:
            await asyncio.sleep(0.1)
        check("a warm container is started up front", len(h.manager._warm) == 1)
        check("it is created with no network at all", h.backend.created[0].network == "none",
              "an unclaimed container must not be able to talk to anything")

        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("the first request is served by the warm container", response.status_code == 200)
        check("no new container was created for it", len(h.backend.claims) == 1)
        check("the claimed container is on the user's network", h.backend.claims[0].network != "none")
        check("it is attributed to the user", h.backend.claims[0].scope.user_id == "u1")
        check("the counter records a warm claim", h.manager.status()["counters"]["claimed_warm"] == 1)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not h.manager._warm:
            await asyncio.sleep(0.1)
        check("the pool refills behind it", len(h.manager._warm) == 1)


async def test_isolation_selfcheck() -> None:
    print("\nisolation self-check")
    from otproxy.ids import Scope

    async with Harness() as h:
        h.backend.docker.exec_output = "internet OSError\nhost OSError\n"
        report = await h.manager._verify_isolation(await h.manager.acquire(Scope("u1")))
        check("a sandbox with no route anywhere passes", report.ok)

        h.manager._isolation = None
        h.backend.docker.exec_output = "internet open\nhost ConnectionRefusedError\n"
        report = await h.manager._verify_isolation(await h.manager.acquire(Scope("u1")))
        check("reaching the internet is reported", report.internet == "reachable")
        check("a refused connection to the host still counts as reachable",
              report.host == "reachable", "the packet arrived, only the port was closed")
        check("that is not a pass", not report.ok)

        h.manager._isolation = None
        h.backend.docker.exec_output = 'OCI runtime exec failed: "python3": not found'
        report = await h.manager._verify_isolation(await h.manager.acquire(Scope("u1")))
        check("a probe that could not run is unknown, not a hole", report.internet == "unknown")
        check("and not a pass either", not report.ok)

    async with Harness(OTPROXY_REQUIRE_ISOLATION="true") as strict:
        strict.backend.docker.exec_output = "internet open\nhost open\n"
        strict.manager._isolation = None
        response = await strict.client.post("/execute", json={"command": "x"}, headers=strict.auth("u1"))
        check("with REQUIRE_ISOLATION a failing check refuses the request", response.status_code == 502)
        response = await strict.client.post("/execute", json={"command": "x"}, headers=strict.auth("u2"))
        check("and keeps refusing, rather than only the first one", response.status_code == 502)


async def test_failures() -> None:
    print("\nwhen a sandbox cannot be started")
    from otproxy.sandbox import SandboxError

    async with Harness() as h:
        h.backend.fail_next_create = SandboxError("sandbox failed to start: exec: operation not permitted")
        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("the caller gets a 502, not a hang", response.status_code == 502)
        check("the reason is passed on", "operation not permitted" in response.text)
        response = await h.client.post("/execute", json={"command": "x"}, headers=h.auth("u1"))
        check("the next attempt is not poisoned", response.status_code == 200)


async def main() -> int:
    async with Harness() as h:
        await test_public_endpoints(h)
    async with Harness() as h:
        await test_authentication(h)
    async with Harness() as h:
        await test_routing(h)
        await test_streaming_and_limits(h)
        await test_websocket(h)
        await test_admin(h)
    await test_body_limit()
    await test_capacity()
    await test_reaper()
    await test_isolation_selfcheck()
    await test_warm_pool()
    await test_policies()
    await test_sandbox_clients_refused()
    await test_failures()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
