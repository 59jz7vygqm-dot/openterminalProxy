"""A small async client for the Docker Engine API.

Why not docker-py: it is synchronous, so every call would need a thread, and it
wraps the API in its own model layer that lags behind the daemon.  The proxy
needs maybe fifteen endpoints and wants exact control over HostConfig, so it
speaks the HTTP API directly over the socket -- the same thing the CLI does.

Paths are unversioned, which makes the daemon answer with its current API
version.  Everything used here has been stable since API 1.41 (Docker 20.10).
"""

from __future__ import annotations

import json
import os
import struct
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from . import log

logger = log.get("docker")


class DockerError(RuntimeError):
    """A non-2xx answer from the daemon.  Carries the status and its message."""

    def __init__(self, status: int, message: str, endpoint: str = "") -> None:
        super().__init__(f"docker {status} on {endpoint}: {message}" if endpoint else f"docker {status}: {message}")
        self.status = status
        self.message = message

    @property
    def is_not_found(self) -> bool:
        return self.status == 404

    @property
    def is_conflict(self) -> bool:
        return self.status == 409


def _filters(**kwargs: Any) -> str:
    """Build the JSON-encoded ``filters`` query parameter."""
    return json.dumps({key: value for key, value in kwargs.items() if value})


class DockerClient:
    """Thin wrapper.  One client, reused; the daemon multiplexes fine."""

    def __init__(self, host: Optional[str] = None, timeout: float = 120.0) -> None:
        host = host or os.environ.get("DOCKER_HOST") or "unix:///var/run/docker.sock"
        self._description = host
        if host.startswith("unix://"):
            path = host[len("unix://"):]
            transport = httpx.AsyncHTTPTransport(uds=path, retries=0)
            base_url = "http://docker"
        elif host.startswith(("tcp://", "http://", "https://")):
            scheme, _, rest = host.partition("://")
            base_url = f"{'https' if scheme == 'https' else 'http'}://{rest.rstrip('/')}"
            transport = httpx.AsyncHTTPTransport(retries=0)
        else:
            raise ValueError(f"DOCKER_HOST: cannot use {host!r} (expected unix:// or tcp://)")
        # No proxy for the daemon: an HTTPS_PROXY in the environment would
        # otherwise swallow these calls.
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=10.0),
            trust_env=False,
        )

    @property
    def description(self) -> str:
        return self._description

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        expect_json: bool = True,
    ) -> Any:
        response = await self._client.request(
            method,
            path,
            params=params,
            json=body,
            headers={"Content-Type": "application/json"} if body is not None else None,
        )
        if response.status_code >= 400:
            raise DockerError(response.status_code, _error_message(response), f"{method} {path}")
        if not expect_json or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # daemon
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        response = await self._client.get("/_ping")
        return response.status_code == 200

    async def version(self) -> Dict[str, Any]:
        return await self._request("GET", "/version")

    async def info(self) -> Dict[str, Any]:
        return await self._request("GET", "/info")

    # ------------------------------------------------------------------
    # images
    # ------------------------------------------------------------------

    async def image_exists(self, image: str) -> bool:
        try:
            await self._request("GET", f"/images/{quote(image, safe='')}/json")
            return True
        except DockerError as exc:
            if exc.is_not_found:
                return False
            raise

    async def pull(self, image: str) -> None:
        """Pull an image, streaming the progress away to the log.

        The daemon answers with a stream of JSON objects and only reports a
        failure inside the stream, so the body has to be read to the end before
        the pull can be called successful.
        """
        if "@" in image:                    # pinned by digest: no tag to split off
            name, tag = image, ""
        else:
            name, _, tag = image.rpartition(":")
            if not name or "/" in tag:      # "repo/name", or a registry port, without a tag
                name, tag = image, "latest"
        params = {"fromImage": name}
        if tag:
            params["tag"] = tag
        last_error = None
        async with self._client.stream(
            "POST", "/images/create", params=params, timeout=httpx.Timeout(1800.0, connect=10.0)
        ) as response:
            if response.status_code >= 400:
                await response.aread()
                raise DockerError(response.status_code, _error_message(response), "POST /images/create")
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if "error" in event:
                    last_error = str(event["error"])
        if last_error:
            raise DockerError(500, last_error, "POST /images/create")

    # ------------------------------------------------------------------
    # containers
    # ------------------------------------------------------------------

    async def create_container(self, name: str, spec: Dict[str, Any]) -> str:
        created = await self._request("POST", "/containers/create", params={"name": name}, body=spec)
        return created["Id"]

    async def start_container(self, container: str) -> None:
        await self._request("POST", f"/containers/{quote(container)}/start", expect_json=False)

    async def stop_container(self, container: str, timeout: int = 5) -> None:
        try:
            await self._request(
                "POST", f"/containers/{quote(container)}/stop", params={"t": timeout}, expect_json=False
            )
        except DockerError as exc:
            if not (exc.is_not_found or exc.status == 304):
                raise

    async def remove_container(self, container: str, *, force: bool = True, volumes: bool = True) -> None:
        try:
            await self._request(
                "DELETE",
                f"/containers/{quote(container)}",
                params={"force": int(force), "v": int(volumes)},
                expect_json=False,
            )
        except DockerError as exc:
            if not exc.is_not_found:
                raise

    async def rename_container(self, container: str, name: str) -> None:
        """Rename a container.

        Used when a warm container is handed to a user: the sandbox's name is
        derived from the user's scope, and keeping that invariant means a
        restarted proxy can find existing sandboxes by name alone.
        """
        await self._request(
            "POST", f"/containers/{quote(container)}/rename", params={"name": name}, expect_json=False
        )

    async def inspect_container(self, container: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._request("GET", f"/containers/{quote(container)}/json")
        except DockerError as exc:
            if exc.is_not_found:
                return None
            raise

    async def list_containers(self, *, label: Optional[str] = None, all_states: bool = True) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"all": int(all_states)}
        if label:
            params["filters"] = _filters(label=[label])
        return await self._request("GET", "/containers/json", params=params) or []

    async def container_logs(self, container: str, *, tail: int = 50) -> str:
        """Return recent output, de-multiplexed, for an error message.

        Without a TTY the daemon frames stdout and stderr in an eight-byte
        header per chunk; printing the raw body would show control bytes.
        """
        try:
            response = await self._client.get(
                f"/containers/{quote(container)}/logs",
                params={"stdout": 1, "stderr": 1, "tail": tail},
            )
        except httpx.HTTPError as exc:
            return f"(log unavailable: {exc})"
        if response.status_code >= 400:
            return f"(log unavailable: {_error_message(response)})"
        return demultiplex(response.content).decode("utf-8", "replace").strip()

    async def exec_run(
        self, container: str, cmd: List[str], *, timeout: float = 30.0, user: Optional[str] = None
    ) -> "ExecResult":
        """Run a command in a running container and collect its output."""
        created = await self._request(
            "POST",
            f"/containers/{quote(container)}/exec",
            body={
                "AttachStdout": True,
                "AttachStderr": True,
                "AttachStdin": False,
                "Tty": False,
                "Cmd": cmd,
                **({"User": user} if user else {}),
            },
        )
        exec_id = created["Id"]
        response = await self._client.post(
            f"/exec/{exec_id}/start",
            json={"Detach": False, "Tty": False},
            headers={"Content-Type": "application/json"},
            timeout=httpx.Timeout(timeout, connect=10.0),
        )
        if response.status_code >= 400:
            raise DockerError(response.status_code, _error_message(response), "POST /exec/start")
        output = demultiplex(response.content).decode("utf-8", "replace")
        info = await self._request("GET", f"/exec/{exec_id}/json")
        return ExecResult(exit_code=int(info.get("ExitCode") or 0), output=output)

    # ------------------------------------------------------------------
    # networks
    # ------------------------------------------------------------------

    async def create_network(self, name: str, spec: Dict[str, Any]) -> str:
        created = await self._request("POST", "/networks/create", body={"Name": name, **spec})
        return created["Id"]

    async def inspect_network(self, name: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._request("GET", f"/networks/{quote(name)}")
        except DockerError as exc:
            if exc.is_not_found:
                return None
            raise

    async def list_networks(self, *, label: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if label:
            params["filters"] = _filters(label=[label])
        return await self._request("GET", "/networks", params=params) or []

    async def remove_network(self, name: str) -> None:
        try:
            await self._request("DELETE", f"/networks/{quote(name)}", expect_json=False)
        except DockerError as exc:
            if not exc.is_not_found:
                raise

    async def connect_network(self, network: str, container: str) -> None:
        try:
            await self._request(
                "POST",
                f"/networks/{quote(network)}/connect",
                body={"Container": container, "EndpointConfig": {}},
                expect_json=False,
            )
        except DockerError as exc:
            # "already exists in network" is the desired state, not a failure.
            if exc.status == 403 and "already exists" in exc.message:
                return
            raise

    async def disconnect_network(self, network: str, container: str, *, force: bool = True) -> None:
        try:
            await self._request(
                "POST",
                f"/networks/{quote(network)}/disconnect",
                body={"Container": container, "Force": force},
                expect_json=False,
            )
        except DockerError as exc:
            if not exc.is_not_found:
                raise

    # ------------------------------------------------------------------
    # volumes
    # ------------------------------------------------------------------

    async def create_volume(self, name: str, labels: Dict[str, str]) -> None:
        await self._request("POST", "/volumes/create", body={"Name": name, "Labels": labels})

    async def remove_volume(self, name: str) -> None:
        try:
            await self._request("DELETE", f"/volumes/{quote(name)}", params={"force": 1}, expect_json=False)
        except DockerError as exc:
            if not exc.is_not_found:
                raise

    async def list_volumes(self, *, label: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if label:
            params["filters"] = _filters(label=[label])
        answer = await self._request("GET", "/volumes", params=params) or {}
        return answer.get("Volumes") or []


class ExecResult:
    __slots__ = ("exit_code", "output")

    def __init__(self, exit_code: int, output: str) -> None:
        self.exit_code = exit_code
        self.output = output

    def __repr__(self) -> str:  # pragma: no cover -- debugging aid
        return f"ExecResult(exit_code={self.exit_code}, output={self.output!r})"


def demultiplex(payload: bytes) -> bytes:
    """Strip Docker's stream framing (8-byte header: stream, 3 pad, 4 length).

    A body that does not look framed is returned unchanged, which is what a TTY
    container sends.
    """
    output = bytearray()
    offset = 0
    length = len(payload)
    while offset + 8 <= length:
        stream_type = payload[offset]
        if stream_type not in (0, 1, 2) or payload[offset + 1 : offset + 4] != b"\x00\x00\x00":
            return payload
        (size,) = struct.unpack(">I", payload[offset + 4 : offset + 8])
        chunk = payload[offset + 8 : offset + 8 + size]
        if len(chunk) < size:
            output.extend(chunk)
            return bytes(output)
        output.extend(chunk)
        offset += 8 + size
    if offset == 0:
        return payload
    return bytes(output)


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip()[:400] or response.reason_phrase
    if isinstance(payload, dict):
        return str(payload.get("message") or payload)[:400]
    return str(payload)[:400]
