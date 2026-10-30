"""Forwarding, HTTP and WebSocket, between Open WebUI and one sandbox.

Two rules shape this module.

**Transparent.**  Open WebUI treats the terminal server as an OpenAPI tool
server: it reads its schema and then calls whatever that schema advertises.  So
the proxy forwards methods, paths, query strings, bodies and status codes
unchanged rather than modelling individual endpoints -- including the file
upload and download paths, which means request and response bodies are streamed,
not buffered.

**The container's credential never leaves the proxy.**  The bearer token Open
WebUI sends is checked here and replaced with the key of the container the
request is routed to.  For WebSockets the same swap happens inside the protocol:
Open Terminal authenticates the socket with its first message, so the proxy
reads that frame, validates it, and sends its own.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

import httpx
import websockets
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask
from starlette.websockets import WebSocketDisconnect, WebSocketState

from . import log

logger = log.get("proxy")

#: Connection-level headers must not be forwarded: they describe the hop, not
#: the message, and passing them on breaks keep-alive and chunked encoding.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

#: Dropped from the request as well: host belongs to the next hop, the
#: Authorization header is replaced, and content-length is recomputed.
REQUEST_DROP = HOP_BY_HOP | {"host", "authorization", "content-length", "expect"}

#: Dropped from the response: the server and date of the sandbox are noise, and
#: Starlette writes its own.
RESPONSE_DROP = HOP_BY_HOP | {"server", "date"}

METHODS_WITHOUT_BODY = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})


class BodyTooLarge(Exception):
    """The request body went past OTPROXY_MAX_BODY."""


def request_headers(incoming: Iterable[Tuple[str, str]], api_key: str) -> List[Tuple[bytes, bytes]]:
    headers = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in incoming
        if name.lower() not in REQUEST_DROP
    ]
    headers.append((b"authorization", f"Bearer {api_key}".encode("latin-1")))
    return headers


def response_headers(incoming: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    return {name: value for name, value in incoming if name.lower() not in RESPONSE_DROP}


class HttpForwarder:
    def __init__(self, *, request_timeout: float, connect_timeout: float, max_body: int) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(request_timeout, connect=connect_timeout),
            # The sandbox is an IP on a private bridge; an HTTPS_PROXY in the
            # environment must not be consulted for it.
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
        self._max_body = max_body

    async def close(self) -> None:
        await self._client.aclose()

    async def forward(self, request: Request, base_url: str, api_key: str, path: str) -> Response:
        url = httpx.URL(f"{base_url}/{path.lstrip('/')}")
        if request.url.query:
            url = url.copy_with(query=request.url.query.encode("latin-1"))

        content: Optional[AsyncIterator[bytes]] = None
        if request.method.upper() not in METHODS_WITHOUT_BODY:
            content = self._limited(request)

        upstream = self._client.build_request(
            request.method,
            url,
            headers=request_headers(request.headers.items(), api_key),
            content=content,
        )
        try:
            response = await self._client.send(upstream, stream=True)
        except BodyTooLarge:
            return JSONResponse(
                {"detail": f"request body exceeds the configured limit of {self._max_body} bytes"},
                status_code=413,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            logger.warning("sandbox at %s refused the connection: %s", base_url, exc)
            return JSONResponse({"detail": "the sandbox is not reachable"}, status_code=502)
        except httpx.ReadTimeout:
            return JSONResponse({"detail": "the sandbox did not answer in time"}, status_code=504)
        except httpx.HTTPError as exc:
            logger.warning("forwarding to %s failed: %s", base_url, exc)
            return JSONResponse({"detail": "the sandbox could not be reached"}, status_code=502)

        # aiter_raw, not aiter_bytes: the body is passed on exactly as it
        # arrived, so Content-Encoding and Content-Length stay truthful.
        return StreamingResponse(
            response.aiter_raw(),
            status_code=response.status_code,
            headers=response_headers(response.headers.items()),
            background=BackgroundTask(response.aclose),
        )

    async def _limited(self, request: Request) -> AsyncIterator[bytes]:
        seen = 0
        async for chunk in request.stream():
            seen += len(chunk)
            if self._max_body and seen > self._max_body:
                raise BodyTooLarge()
            yield chunk


class WebSocketForwarder:
    """Bridge one browser terminal session to the sandbox's PTY endpoint."""

    def __init__(self, *, open_timeout: float) -> None:
        self._open_timeout = open_timeout

    async def read_auth(self, ws: WebSocket, timeout: float = 10.0) -> Dict[str, Any]:
        """Read Open Terminal's first-message auth frame.

        Returns the parsed payload.  Raises :class:`ValueError` when the client
        sends something else, which the caller turns into a close code.
        """
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=timeout)
        except asyncio.TimeoutError:
            raise ValueError("no auth message within 10s") from None
        except (WebSocketDisconnect, RuntimeError) as exc:
            raise ValueError(f"client went away before authenticating: {exc}") from None
        try:
            payload = json.loads(raw)
        except ValueError:
            raise ValueError("auth message is not JSON") from None
        if not isinstance(payload, dict) or payload.get("type") != "auth":
            raise ValueError("first message must be {\"type\": \"auth\", ...}")
        return payload

    async def pump(
        self,
        ws: WebSocket,
        url: str,
        *,
        api_key: str,
        headers: Dict[str, str],
        chat_id: str = "",
    ) -> None:
        """Connect upstream, authenticate as ourselves, then copy frames."""
        try:
            upstream = await websockets.connect(
                url,
                additional_headers=headers,
                open_timeout=self._open_timeout,
                ping_interval=20,
                ping_timeout=20,
                max_size=None,          # terminal output is not bounded by us
                close_timeout=5,
            )
        except Exception as exc:  # noqa: BLE001 -- websockets raises many shapes
            logger.warning("could not open the sandbox terminal socket: %s", exc)
            await _close(ws, 1011, "sandbox terminal unavailable")
            return

        try:
            await upstream.send(json.dumps({"type": "auth", "token": api_key, "chat_id": chat_id}))

            async def client_to_sandbox() -> None:
                while True:
                    message = await ws.receive()
                    kind = message.get("type")
                    if kind == "websocket.disconnect":
                        return
                    if message.get("bytes"):
                        await upstream.send(message["bytes"])
                    elif message.get("text"):
                        await upstream.send(message["text"])

            async def sandbox_to_client() -> None:
                async for message in upstream:
                    if isinstance(message, bytes):
                        await ws.send_bytes(message)
                    else:
                        await ws.send_text(message)

            tasks = [
                asyncio.create_task(client_to_sandbox(), name="otproxy-ws-up"),
                asyncio.create_task(sandbox_to_client(), name="otproxy-ws-down"),
            ]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    exception = task.exception()
                    if exception and not isinstance(
                        exception, (WebSocketDisconnect, websockets.exceptions.ConnectionClosed)
                    ):
                        logger.debug("terminal socket ended: %s", exception)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Hand the sandbox's close code back to the client: Open Terminal
            # uses 4001/4004/4009 to say *why*, and Open WebUI shows it.
            code = getattr(upstream, "close_code", None)
            reason = getattr(upstream, "close_reason", "") or ""
            await upstream.close()
            await _close(ws, code if isinstance(code, int) and 1000 <= code < 5000 else 1000, reason)


async def _close(ws: WebSocket, code: int, reason: str = "") -> None:
    if ws.client_state is WebSocketState.DISCONNECTED:
        return
    try:
        await ws.close(code=code, reason=reason[:120])
    except (RuntimeError, WebSocketDisconnect):
        pass
