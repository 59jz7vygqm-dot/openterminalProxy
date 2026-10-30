"""A fake Open Terminal server and a fake Docker backend.

Together they let the whole proxy run -- routing, authentication, streaming,
WebSockets, the lifecycle rules -- with no Docker daemon and no image, which is
what makes these tests runnable anywhere.  The Docker-specific half is covered
separately by tests/test_docker.py, which needs a real daemon.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uvicorn

from otproxy.config import Policy, Settings
from otproxy.ids import Scope
from otproxy.sandbox import Sandbox

UPSTREAM_KEY = "upstream-container-key"


# ----------------------------------------------------------------------
# a stand-in for the Open Terminal container
# ----------------------------------------------------------------------


class FakeTerminal:
    """Raw ASGI, so the WebSocket framing is exactly what we assert on."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.ws_auth_tokens: List[str] = []

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        path = scope["path"]
        headers = {key.decode(): value.decode() for key, value in scope["headers"]}
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.requests.append(
            {
                "method": scope["method"],
                "path": path,
                "query": scope["query_string"].decode(),
                "headers": headers,
                "body_len": len(body),
            }
        )
        authorised = headers.get("authorization") == f"Bearer {UPSTREAM_KEY}"

        if path == "/health":
            return await _json(send, 200, {"status": "ok"})
        if path == "/api/config":
            return await _json(send, 200, {"features": {"terminal": True, "notebooks": True, "system": True}})
        if path == "/openapi.json":
            return await _json(send, 200, {"openapi": "3.1.0", "paths": {"/execute": {}}, "nonce": time.time()})
        if not authorised:
            return await _json(send, 401, {"detail": "Invalid API key"})
        if path == "/system":
            return await _json(send, 200, {"prompt": "you are in a sandbox"})
        if path == "/execute":
            return await _json(
                send,
                200,
                {
                    "id": "p1",
                    "echo": body.decode("utf-8", "replace"),
                    "user": headers.get("x-user-id", ""),
                    "session": headers.get("x-session-id", ""),
                    "context": headers.get("x-terminal-context-id", ""),
                },
            )
        if path == "/files/upload":
            return await _json(send, 200, {"received": len(body)})
        if path == "/big":
            size = int(dict(_pairs(scope["query_string"].decode())).get("n", "1048576"))
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/octet-stream")]})
            sent = 0
            while sent < size:
                chunk = b"x" * min(65536, size - sent)
                sent += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": sent < size})
            return
        return await _json(send, 404, {"detail": "not found"})

    async def _websocket(self, scope, receive, send) -> None:
        await receive()                      # websocket.connect
        await send({"type": "websocket.accept"})
        message = await receive()
        try:
            payload = json.loads(message.get("text") or "{}")
        except ValueError:
            payload = {}
        token = str(payload.get("token") or "")
        self.ws_auth_tokens.append(token)
        if token != UPSTREAM_KEY:
            await send({"type": "websocket.close", "code": 4001})
            return
        headers = {key.decode(): value.decode() for key, value in scope["headers"]}
        await send({"type": "websocket.send", "text": json.dumps({
            "hello": scope["path"], "user": headers.get("x-user-id", ""), "chat": payload.get("chat_id", ""),
        })})
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("bytes") is not None:
                await send({"type": "websocket.send", "bytes": b"echo:" + message["bytes"]})
            elif message.get("text") is not None:
                await send({"type": "websocket.send", "text": "echo:" + message["text"]})


def _pairs(query: str):
    for item in query.split("&"):
        if "=" in item:
            key, _, value = item.partition("=")
            yield key, value


async def _json(send, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


# ----------------------------------------------------------------------
# running an ASGI app on loopback for the duration of a test
# ----------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    """uvicorn in a thread, bound to loopback only."""

    def __init__(self, app, port: Optional[int] = None) -> None:
        self.port = port or free_port()
        self._config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_config=None, access_log=False,
            lifespan="on", ws_max_size=None,
        )
        self._server = uvicorn.Server(self._config)
        self._thread: Optional[threading.Thread] = None

    def start(self, timeout: float = 20.0) -> "Server":
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return self
            time.sleep(0.02)
        raise RuntimeError(f"server on port {self.port} did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=20)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ws_base(self) -> str:
        return f"ws://127.0.0.1:{self.port}"


# ----------------------------------------------------------------------
# a fake Docker
# ----------------------------------------------------------------------


class FakeDocker:
    def __init__(self) -> None:
        self.containers: Dict[str, Dict[str, Any]] = {}
        self.removed: List[str] = []
        self.exec_output = "internet OSError\nhost OSError\n"
        self.description = "fake"

    async def ping(self) -> bool:
        return True

    async def version(self) -> Dict[str, Any]:
        return {"Version": "fake", "ApiVersion": "1.99"}

    async def close(self) -> None:
        return None

    async def inspect_container(self, container: str) -> Optional[Dict[str, Any]]:
        entry = self.containers.get(container)
        if entry is None:
            return None
        return {
            "Id": container,
            "Name": "/" + entry["name"],
            "State": {"Running": entry["running"]},
            "Config": {"Image": entry["image"], "Labels": {}, "Env": [f"OPEN_TERMINAL_API_KEY={UPSTREAM_KEY}"]},
            "NetworkSettings": {"Networks": {entry["network"]: {"IPAddress": entry["ip"]}}},
            "Created": "2026-01-01T00:00:00Z",
        }

    async def container_logs(self, container: str, tail: int = 50) -> str:
        return "(fake log)"

    async def exec_run(self, container: str, cmd: List[str], timeout: float = 30.0, user=None):
        class Result:
            exit_code = 0
            output = self.exec_output

        return Result()

    async def remove_container(self, container: str, force: bool = True, volumes: bool = True) -> None:
        self.containers.pop(container, None)
        self.removed.append(container)

    async def remove_volume(self, name: str) -> None:
        return None

    async def list_volumes(self, label: Optional[str] = None):
        return []


class FakeBackend:
    """Hands out sandboxes that point at one fake Open Terminal server."""

    def __init__(self, settings: Settings, upstream_port: int) -> None:
        self.settings = settings
        self.docker = FakeDocker()
        self.upstream_port = upstream_port
        self.created: List[Sandbox] = []
        self.destroyed: List[Sandbox] = []
        self.claims: List[Sandbox] = []
        self.networks: List[str] = []
        self._counter = 0
        self.owner_label = "fake/owned=true"
        self.fail_next_create: Optional[Exception] = None

    async def resolve_self(self) -> Optional[str]:
        return None

    async def adopt_all(self):
        return [], []

    async def ensure_network(self, scope, name: str, policy_id: str = "") -> str:
        if name not in self.networks:
            self.networks.append(name)
        return name

    async def network_gateway(self, name: str) -> str:
        return "10.88.0.1"

    async def prune_networks(self, keep) -> int:
        self.networks = [name for name in self.networks if name in keep]
        return 0

    async def prune_volumes(self, keep) -> int:
        return 0

    async def create(self, *, scope: Optional[Scope], policy: Optional[Policy],
                     role: str = "sandbox", name: Optional[str] = None, network: Optional[str] = None) -> Sandbox:
        if self.fail_next_create is not None:
            error, self.fail_next_create = self.fail_next_create, None
            raise error
        self._counter += 1
        container_id = f"fake{self._counter:04d}"
        network_name = network or f"net-{self._counter}"
        sandbox = Sandbox(
            key=scope.key if scope else container_id,
            name=name or (f"sbx-{scope.key}" if scope else f"warm-{self._counter}"),
            container_id=container_id,
            api_key=UPSTREAM_KEY,
            ip="127.0.0.1",
            port=self.upstream_port,
            network=network_name,
            scope=scope,
            policy_id=policy.id if policy else "",
        )
        self.docker.containers[container_id] = {
            "name": sandbox.name, "running": True, "ip": "127.0.0.1",
            "network": network_name, "image": self.settings.image_for(policy),
        }
        self.created.append(sandbox)
        return sandbox

    async def claim_warm(self, warm: Sandbox, scope: Scope, policy: Optional[Policy]) -> Sandbox:
        warm.key = scope.key
        warm.scope = scope
        warm.name = f"sbx-{scope.key}"
        warm.network = await self.ensure_network(scope, f"net-{scope.key}")
        warm.ready = False
        self.docker.containers[warm.container_id].update(name=warm.name, network=warm.network)
        self.claims.append(warm)
        return warm

    async def destroy(self, sandbox: Sandbox) -> None:
        self.destroyed.append(sandbox)
        await self.docker.remove_container(sandbox.container_id)
