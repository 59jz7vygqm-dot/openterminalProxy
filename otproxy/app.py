"""The HTTP surface Open WebUI talks to.

Routes fall into three groups:

* **Answered here, without a container.**  ``/health``, ``/api/config`` and
  ``/openapi.json``.  Open WebUI reads the schema with no user attached, and
  gives ``/api/config`` three seconds -- a container start does not fit in
  three seconds, so these come out of a cache filled from the image.
* **Forwarded to the caller's sandbox.**  Everything else, including the
  interactive WebSocket.  The sandbox is created on demand.
* **Administrative.**  ``/api/v1/status``, ``/api/v1/terminals`` and
  ``/api/v1/policies``, behind their own key.  Those three prefixes are the ones
  Open WebUI refuses to proxy from a browser, so they cannot be reached through
  an Open WebUI session even if the proxy is otherwise visible.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from contextlib import asynccontextmanager
from urllib.parse import quote
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from . import config, ids, log, share
from .ids import InvalidIdentity, Scope
from .manager import CapacityError, SandboxManager
from .proxy import HttpForwarder, UpstreamUnreachable, WebSocketForwarder
from .sandbox import Sandbox, SandboxError

logger = log.get("app")

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

#: How often an open terminal socket counts as activity.  A shell somebody is
#: reading sends nothing, and without this the reaper would remove the container
#: under it after OTPROXY_IDLE_TIMEOUT.  Lowered by the tests.
WS_KEEPALIVE_SECONDS = 15.0


def create_app(settings: Optional[config.Settings] = None, manager: Optional[SandboxManager] = None) -> FastAPI:
    settings = settings or config.load()
    log.setup(settings.log_level, settings.log_json)
    state: Dict[str, Any] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state["manager"] = manager or SandboxManager(settings)
        state["http"] = HttpForwarder(
            request_timeout=settings.request_timeout,
            connect_timeout=settings.connect_timeout,
            max_body=settings.max_body_bytes,
        )
        state["ws"] = WebSocketForwarder(open_timeout=max(10.0, settings.connect_timeout * 2))
        state["started"] = time.time()
        for note in settings.notes:
            logger.warning("%s", note)
        await state["manager"].start()
        logger.info(
            "listening on %s:%d -- image=%s limit=%d idle=%.0fs network=%s",
            settings.host, settings.port, settings.image, settings.max_sandboxes,
            settings.idle_timeout, settings.network_mode,
        )
        try:
            yield
        finally:
            await state["http"].close()
            await state["manager"].close()

    app = FastAPI(
        title="Open Terminal proxy",
        # The proxy's own schema would collide with the sandbox schema that Open
        # WebUI reads from /openapi.json, so the generated one is turned off.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    sandbox_range = ipaddress.ip_network(settings.supernet, strict=False)

    def from_sandbox(client_host: Optional[str]) -> bool:
        if not settings.reject_sandbox_clients or not client_host:
            return False
        try:
            return ipaddress.ip_address(client_host) in sandbox_range
        except ValueError:
            return False

    @app.middleware("http")
    async def refuse_sandbox_clients(request: Request, call_next):
        """A sandbox shares a bridge with the proxy, so it can see this port.

        It has no key to use it with, but there is no reason to answer it.
        """
        if from_sandbox(request.client.host if request.client else None):
            logger.warning("refused a request from inside the sandbox range (%s)", request.client.host)
            return JSONResponse({"detail": "not available from here"}, status_code=403)
        return await call_next(request)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def mgr() -> SandboxManager:
        return state["manager"]

    def authorised(request: Request) -> bool:
        return ids.matches_any_key(ids.bearer(request.headers.get("authorization")), settings.api_keys)

    def unauthorised() -> JSONResponse:
        return JSONResponse({"detail": "invalid API key"}, status_code=401)

    def admin_ok(request: Request) -> Optional[JSONResponse]:
        if not settings.admin_key:
            return JSONResponse(
                {"detail": "the admin API is disabled; set OTPROXY_ADMIN_KEY to enable it"}, status_code=404
            )
        token = ids.bearer(request.headers.get("authorization"))
        if not ids.matches_any_key(token, [settings.admin_key]):
            return JSONResponse({"detail": "invalid admin key"}, status_code=401)
        return None

    def scope_of(request_headers, query, policy_id: str) -> Scope:
        # X-User-Id is what an Open Terminal connection sends.  A generic tool
        # server or an MCP connection does not send it at all -- those paths
        # only carry the user's id as X-OpenWebUI-User-Id, and only when the
        # admin turned ENABLE_FORWARD_USER_INFO_HEADERS on.  Accepting both
        # means the proxy works either way; it does not make the second one
        # more trustworthy, since both arrive from the same authenticated
        # connection.
        user_id = (
            request_headers.get("x-user-id")
            or request_headers.get("x-openwebui-user-id")
            or query.get("user_id")
            or ""
        )
        user_id = ids.check_id(user_id, what="X-User-Id")
        context_id = ""
        if settings.scope_by_context:
            raw_context = request_headers.get("x-terminal-context-id", "")
            if raw_context:
                context_id = ids.check_id(raw_context, what="X-Terminal-Context-Id")
        return Scope(user_id=user_id, context_id=context_id, policy_id=policy_id)

    def policy_of(policy_id: str):
        if not policy_id:
            return None
        policy = settings.policy(policy_id)
        if policy is None:
            raise LookupError(policy_id)
        return policy

    async def sandbox_for(request: Request, policy_id: str) -> Tuple[Optional[Sandbox], Optional[Response]]:
        """Resolve the caller to a ready sandbox, or to the response to send."""
        try:
            policy = policy_of(policy_id)
        except LookupError:
            return None, JSONResponse(
                {"detail": f"unknown policy {policy_id!r}; configured: {sorted(settings.policies) or 'none'}"},
                status_code=404,
            )
        try:
            scope = scope_of(request.headers, request.query_params, policy_id)
        except InvalidIdentity as exc:
            # An Open Terminal connection always sends X-User-Id; a generic
            # tool-server or MCP connection never does.  Whoever reads this is
            # usually the person who can fix it -- in a chat, through the
            # model -- so the answer goes with it.
            return None, JSONResponse(
                {
                    "detail": (
                        f"{exc}. This proxy gives every user their own sandbox and will not share one. "
                        "Either register it under Admin > Integrations > Open Terminal, or add a custom "
                        "header to the connection: X-User-Id = {{USER_ID}}"
                    )
                },
                status_code=400,
            )
        try:
            return await mgr().acquire(scope, policy), None
        except CapacityError as exc:
            return None, JSONResponse(
                {"detail": "no sandbox slot available, try again shortly"},
                status_code=503,
                headers={"Retry-After": str(exc.retry_after)},
            )
        except SandboxError as exc:
            logger.error("could not give %s a sandbox: %s", scope.describe(), exc)
            return None, JSONResponse(
                {"detail": str(exc).splitlines()[0] or "the sandbox could not be started"}, status_code=502
            )

    # ------------------------------------------------------------------
    # answered without a container
    # ------------------------------------------------------------------

    @app.get("/health")
    async def health() -> Response:
        """Liveness, and the endpoint the Open WebUI setup guide tells people to curl."""
        return JSONResponse({"status": "ok", "proxy": "otproxy"})

    @app.get("/readyz")
    async def readyz() -> Response:
        try:
            alive = await mgr().backend.docker.ping()
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"status": "error", "docker": str(exc)}, status_code=503)
        if not alive:
            return JSONResponse({"status": "error", "docker": "unreachable"}, status_code=503)
        # Deliberately thin: this endpoint needs no key, so it says whether the
        # proxy can work and how full it is, and nothing about the configuration.
        return JSONResponse({"status": "ok", "sandboxes": mgr().in_use, "limit": settings.max_sandboxes})

    async def cached(path: str) -> Response:
        try:
            status, body, content_type = await mgr().cached_get(path)
        except CapacityError:
            return JSONResponse(
                {"detail": "no sandbox slot available to read the schema from"},
                status_code=503,
                headers={"Retry-After": "30"},
            )
        except SandboxError as exc:
            logger.error("could not read %s from a sandbox: %s", path, exc)
            return JSONResponse({"detail": f"could not read {path} from a sandbox"}, status_code=502)
        return Response(content=body, status_code=status, media_type=content_type)

    @app.get("/openapi.json")
    async def openapi_schema() -> Response:
        """The sandbox image's own schema, plus the tools the proxy itself adds.

        Open WebUI builds its tool definitions from this, so share_file has to
        appear here or the model never learns it exists.
        """
        answer = await cached("/openapi.json")
        if not settings.sharing_enabled or answer.status_code != 200:
            return answer
        try:
            schema = json.loads(bytes(answer.body))
        except ValueError:
            return answer
        path, definition = share.schema_fragment(max(1, int(settings.download_ttl // 60)))
        schema.setdefault("paths", {})[path] = definition
        return JSONResponse(schema)

    @app.get("/api/config")
    async def api_config() -> Response:
        """The image's feature flags, with the operator's overrides applied.

        Open WebUI reads this to decide what to offer in its side pane, so
        OTPROXY_UI_FEATURES can take a part of that interface away without
        changing anything inside the sandbox.
        """
        answer = await cached("/api/config")
        if not settings.ui_features or answer.status_code != 200:
            return answer
        try:
            payload = json.loads(bytes(answer.body))
        except ValueError:
            return answer
        features = payload.get("features")
        if not isinstance(features, dict):
            features = {}
        payload["features"] = {**features, **settings.ui_features}
        return JSONResponse(payload)

    @app.get("/share")
    async def share_file(request: Request, path: str = "") -> Response:
        """Give the caller a link their user can open.  See otproxy/share.py."""
        if not settings.sharing_enabled:
            return JSONResponse(
                {"detail": "file sharing is not configured; set OTPROXY_PUBLIC_URL"}, status_code=404
            )
        if not authorised(request):
            return unauthorised()
        if not path:
            return JSONResponse({"detail": "path is required"}, status_code=422)
        sandbox, failure = await sandbox_for(request, "")
        if failure is not None:
            return failure
        assert sandbox is not None

        # The sandbox resolves the path itself, so a relative one works and what
        # comes back is the path the file really has.
        probe_url = f"{sandbox.base_url}/files/display?path={quote(path, safe='')}"
        answer: Dict[str, Any] = {}
        try:
            upstream = await state["http"].fetch(probe_url, sandbox.api_key)
            try:
                payload = await upstream.aread()
                if upstream.status_code == 200:
                    answer = json.loads(payload)
            finally:
                await upstream.aclose()
        except (ValueError, OSError) as exc:
            logger.warning("could not resolve %s in %s: %s", path, sandbox.key, exc)
        except Exception as exc:  # noqa: BLE001 -- httpx raises several shapes
            logger.warning("could not resolve %s in %s: %s", path, sandbox.key, exc)
        if not answer.get("exists"):
            return JSONResponse({"detail": f"no such file: {path}"}, status_code=404)

        grant = share.Grant(
            key=sandbox.key,
            path=str(answer.get("path") or path),
            expires=int(time.time() + settings.download_ttl),
        )
        token = share.mint(settings.download_secret, grant)
        url = share.link(settings.public_url, token)
        logger.info("handed out a link to %s for %s", grant.name, sandbox.key)
        return JSONResponse(
            {
                "url": url,
                "markdown": share.markdown_for(grant.name, url),
                "name": grant.name,
                "expires_in_seconds": int(settings.download_ttl),
            }
        )

    @app.get("/d/{token}")
    async def download(token: str) -> Response:
        """Serve one file from one sandbox to a browser, on a signed link."""
        if not settings.sharing_enabled:
            return PlainTextResponse("file sharing is not configured", status_code=404)
        try:
            grant = share.verify(settings.download_secret, token)
        except share.BadToken as exc:
            return PlainTextResponse(str(exc), status_code=403)
        sandbox = mgr().lookup(grant.key)
        if sandbox is None:
            return PlainTextResponse(
                "this workspace is no longer running, so the file is gone", status_code=410
            )
        url = f"{sandbox.base_url}/files/view?path={quote(grant.path, safe='')}"
        try:
            upstream = await state["http"].fetch(url, sandbox.api_key)
        except Exception as exc:  # noqa: BLE001 -- any failure is the same to the browser
            logger.warning("could not read %s for a link: %s", grant.path, exc)
            return PlainTextResponse("the file could not be read", status_code=502)
        if upstream.status_code != 200:
            await upstream.aclose()
            return PlainTextResponse("the file is gone", status_code=404)
        sandbox.touch()
        media_type = upstream.headers.get("content-type", "application/octet-stream")
        inline = media_type.startswith("image/") or media_type == "application/pdf"
        return StreamingResponse(
            upstream.aiter_raw(),
            status_code=200,
            media_type=media_type,
            headers={
                "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{grant.name}"',
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
            background=BackgroundTask(upstream.aclose),
        )

    # ------------------------------------------------------------------
    # administration
    # ------------------------------------------------------------------

    @app.get("/api/v1/status")
    async def admin_status(request: Request) -> Response:
        denied = admin_ok(request)
        if denied:
            return denied
        status = mgr().status()
        status["uptime_seconds"] = round(time.time() - state["started"], 1)
        status["docker"] = mgr().backend.docker.description
        return JSONResponse(status)

    @app.get("/api/v1/terminals")
    async def admin_list(request: Request) -> Response:
        denied = admin_ok(request)
        if denied:
            return denied
        return JSONResponse({"terminals": mgr().listing()})

    @app.delete("/api/v1/terminals/{key}")
    async def admin_delete(key: str, request: Request) -> Response:
        denied = admin_ok(request)
        if denied:
            return denied
        removed = await mgr().release(key)
        return JSONResponse({"removed": removed}, status_code=200 if removed else 404)

    @app.get("/api/v1/policies")
    async def admin_policies(request: Request) -> Response:
        denied = admin_ok(request)
        if denied:
            return denied
        return JSONResponse(
            {
                "policies": {
                    name: {
                        "image": policy.image or settings.image,
                        "memory": policy.memory,
                        "cpus": policy.cpus,
                        "pids": policy.pids,
                        "idle_timeout": policy.idle_timeout,
                        "env_keys": sorted(policy.env),
                    }
                    for name, policy in settings.policies.items()
                }
            }
        )

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        if not settings.metrics_public:
            denied = admin_ok(request)
            if denied:
                return denied
        return PlainTextResponse(mgr().metrics(), media_type="text/plain; version=0.0.4")

    # ------------------------------------------------------------------
    # interactive terminal
    # ------------------------------------------------------------------

    async def terminal_socket(ws: WebSocket, session_id: str, policy_id: str = "") -> None:
        await ws.accept()
        client_host = ws.client.host if ws.client else None
        if from_sandbox(client_host):
            await ws.close(code=4003, reason="not available from here")
            return

        forwarder: WebSocketForwarder = state["ws"]
        try:
            payload = await forwarder.read_auth(ws)
        except ValueError as exc:
            await ws.close(code=4001, reason=str(exc)[:120])
            return
        if not ids.matches_any_key(str(payload.get("token") or ""), settings.api_keys):
            await ws.close(code=4001, reason="invalid API key")
            return

        try:
            policy = policy_of(policy_id)
        except LookupError:
            await ws.close(code=4004, reason=f"unknown policy {policy_id}")
            return
        try:
            scope = scope_of(ws.headers, ws.query_params, policy_id)
        except InvalidIdentity as exc:
            await ws.close(code=4003, reason=str(exc)[:120])
            return

        try:
            sandbox = await mgr().acquire(scope, policy)
        except CapacityError:
            await ws.close(code=4009, reason="no sandbox slot available")
            return
        except SandboxError as exc:
            logger.error("terminal socket for %s has no sandbox: %s", scope.describe(), exc)
            await ws.close(code=1011, reason="sandbox unavailable")
            return

        chat_id = str(payload.get("chat_id") or "")
        headers = {"X-User-Id": scope.user_id}
        session_header = (
            ws.headers.get("x-session-id") or ws.headers.get("x-openwebui-chat-id") or chat_id
        )
        if session_header:
            headers["X-Session-Id"] = session_header
        if scope.context_id:
            headers["X-Terminal-Context-Id"] = scope.context_id

        url = f"ws://{sandbox.ip}:{sandbox.port}/api/terminals/{session_id}"
        if ws.url.query:
            url += f"?{ws.url.query}"
        sandbox.touch()

        async def keep_alive() -> None:
            """An open shell is a user, even while nothing is typed."""
            while True:
                await asyncio.sleep(WS_KEEPALIVE_SECONDS)
                sandbox.touch()

        heartbeat = asyncio.create_task(keep_alive(), name="otproxy-ws-keepalive")
        try:
            await forwarder.pump(ws, url, api_key=sandbox.api_key, headers=headers, chat_id=chat_id)
        finally:
            heartbeat.cancel()

    @app.websocket("/api/terminals/{session_id}")
    async def ws_terminal(ws: WebSocket, session_id: str) -> None:
        await terminal_socket(ws, session_id)

    @app.websocket("/p/{policy_id}/api/terminals/{session_id}")
    async def ws_terminal_with_policy(ws: WebSocket, policy_id: str, session_id: str) -> None:
        await terminal_socket(ws, session_id, policy_id)

    # ------------------------------------------------------------------
    # everything else goes to the caller's sandbox
    # ------------------------------------------------------------------

    async def forward(request: Request, path: str, policy_id: str = "") -> Response:
        if not authorised(request):
            return unauthorised()
        # /system is read once per message with a three-second budget.  Without a
        # user to attribute it to -- and for the literal "system" user Open WebUI
        # uses when it reads a policy's prompt -- it comes from the cache like
        # the schema does, rather than starting a container nobody works in.
        user = (
            request.headers.get("x-user-id")
            or request.headers.get("x-openwebui-user-id")
            or request.query_params.get("user_id")
            or ""
        )
        if path == "system" and user in ("", "system"):
            return await cached("/system")
        # Answered without asking a sandbox: the port list only feeds the pane's
        # Ports tab, and an operator may want that tab to stay empty.
        if settings.hide_ports and path.strip("/") == "ports":
            return JSONResponse({"ports": []})
        sandbox, failure = await sandbox_for(request, policy_id)
        if failure is not None:
            return failure
        assert sandbox is not None
        extra: Dict[str, str] = {}
        # The container is told the identity the proxy actually routed on,
        # under the name Open Terminal reads -- whatever name it arrived under,
        # and whatever else the caller may have put in that header.
        if sandbox.scope is not None:
            extra["X-User-Id"] = sandbox.scope.user_id
        # Open Terminal tracks the working directory per X-Session-Id.  A
        # generic tool server sends the chat as X-OpenWebUI-Chat-Id instead, so
        # it is translated rather than lost.
        if not request.headers.get("x-session-id") and request.headers.get("x-openwebui-chat-id"):
            extra["X-Session-Id"] = request.headers["x-openwebui-chat-id"]
        try:
            return await state["http"].forward(
                request, sandbox.base_url, sandbox.api_key, path, extra_headers=extra or None
            )
        except UpstreamUnreachable:
            # The sandbox died since we last spoke to it.  Replace it and try
            # once -- a body already streamed upstream cannot be sent again, so
            # only requests without one are retried.
            await mgr().invalidate(sandbox)
            if request.method.upper() not in ("GET", "HEAD", "OPTIONS"):
                return JSONResponse(
                    {"detail": "the sandbox had to be restarted, please send that again"},
                    status_code=503,
                    headers={"Retry-After": "1"},
                )
            replacement, failure = await sandbox_for(request, policy_id)
            if failure is not None:
                return failure
            assert replacement is not None
            try:
                return await state["http"].forward(
                    request, replacement.base_url, replacement.api_key, path, extra_headers=extra or None
                )
            except UpstreamUnreachable:
                return JSONResponse({"detail": "the sandbox is not reachable"}, status_code=502)

    @app.api_route("/p/{policy_id}/{path:path}", methods=ALL_METHODS)
    async def forward_with_policy(policy_id: str, path: str, request: Request) -> Response:
        return await forward(request, path, policy_id)

    @app.api_route("/{path:path}", methods=ALL_METHODS)
    async def forward_plain(path: str, request: Request) -> Response:
        return await forward(request, path)

    return app
