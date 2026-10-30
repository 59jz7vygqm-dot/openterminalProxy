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

import ipaddress
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from . import config, ids, log
from .ids import InvalidIdentity, Scope
from .manager import CapacityError, SandboxManager
from .proxy import HttpForwarder, WebSocketForwarder
from .sandbox import Sandbox, SandboxError

logger = log.get("app")

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


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
        user_id = request_headers.get("x-user-id") or query.get("user_id") or ""
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
            # Open WebUI always sends X-User-Id.  Anything else is either a
            # misconfiguration or somebody poking at the port.
            return None, JSONResponse({"detail": str(exc)}, status_code=400)
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
        """The sandbox image's own schema: this is how Open WebUI learns the tools."""
        return await cached("/openapi.json")

    @app.get("/api/config")
    async def api_config() -> Response:
        return await cached("/api/config")

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
        session_header = ws.headers.get("x-session-id", chat_id)
        if session_header:
            headers["X-Session-Id"] = session_header
        if scope.context_id:
            headers["X-Terminal-Context-Id"] = scope.context_id

        url = f"ws://{sandbox.ip}:{sandbox.port}/api/terminals/{session_id}"
        if ws.url.query:
            url += f"?{ws.url.query}"
        sandbox.touch()
        await forwarder.pump(ws, url, api_key=sandbox.api_key, headers=headers, chat_id=chat_id)

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
        user = request.headers.get("x-user-id") or request.query_params.get("user_id") or ""
        if path == "system" and user in ("", "system"):
            return await cached("/system")
        sandbox, failure = await sandbox_for(request, policy_id)
        if failure is not None:
            return failure
        assert sandbox is not None
        return await state["http"].forward(request, sandbox.base_url, sandbox.api_key, path)

    @app.api_route("/p/{policy_id}/{path:path}", methods=ALL_METHODS)
    async def forward_with_policy(policy_id: str, path: str, request: Request) -> Response:
        return await forward(request, path, policy_id)

    @app.api_route("/{path:path}", methods=ALL_METHODS)
    async def forward_plain(path: str, request: Request) -> Response:
        return await forward(request, path)

    return app
