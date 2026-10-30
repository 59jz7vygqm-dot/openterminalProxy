"""Configuration, entirely from the environment, validated once at startup.

Everything is prefixed ``OTPROXY_``.  A bad value is a startup failure with a
message that names the variable -- not a surprise three hours into a shift.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ConfigError(ValueError):
    """Raised for an unusable configuration.  The message names the variable."""


# --------------------------------------------------------------------------
# primitive readers
# --------------------------------------------------------------------------


def _raw(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(f"OTPROXY_{name}")
    if value is None:
        return default
    return value.strip()


def _str(name: str, default: str = "") -> str:
    return _raw(name, default) or ""


def _bool(name: str, default: bool) -> bool:
    value = _raw(name)
    if value is None or value == "":
        return default
    if value.lower() in ("1", "true", "yes", "on"):
        return True
    if value.lower() in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"OTPROXY_{name}: expected a boolean, got {value!r}")


def _int(name: str, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    value = _raw(name)
    if value is None or value == "":
        number = default
    else:
        try:
            number = int(value)
        except ValueError:
            raise ConfigError(f"OTPROXY_{name}: expected an integer, got {value!r}") from None
    if minimum is not None and number < minimum:
        raise ConfigError(f"OTPROXY_{name}: must be >= {minimum}, got {number}")
    if maximum is not None and number > maximum:
        raise ConfigError(f"OTPROXY_{name}: must be <= {maximum}, got {number}")
    return number


def _float(name: str, default: float, minimum: Optional[float] = None) -> float:
    value = _raw(name)
    if value is None or value == "":
        number = default
    else:
        try:
            number = float(value)
        except ValueError:
            raise ConfigError(f"OTPROXY_{name}: expected a number, got {value!r}") from None
    if minimum is not None and number < minimum:
        raise ConfigError(f"OTPROXY_{name}: must be >= {minimum}, got {number}")
    return number


def _list(name: str, default: str = "") -> List[str]:
    return [item.strip() for item in _str(name, default).split(",") if item.strip()]


def _json_dict(name: str, default: str = "{}") -> Dict[str, Any]:
    text = _str(name, default) or default
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"OTPROXY_{name}: not valid JSON ({exc.msg})") from None
    if not isinstance(value, dict):
        raise ConfigError(f"OTPROXY_{name}: expected a JSON object")
    return value


# Docker takes memory as a byte count; humans write "2g".
_SIZE_UNITS = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(text: str, *, what: str) -> int:
    """Turn ``512m`` / ``2g`` / ``1073741824`` into a byte count."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([bkmgt]?)i?b?", text.strip().lower())
    if not match:
        raise ConfigError(f"{what}: expected a size like 512m or 2g, got {text!r}")
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2) or "b"])


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """A named container profile, selected by Open WebUI's ``/p/<id>/`` route.

    Open WebUI appends that prefix when a connection is configured with a
    policy, so supporting it keeps us a drop-in for an orchestrator-type
    connection.  Policies are defined in OTPROXY_POLICIES, not over HTTP:
    container shapes are deployment configuration, not runtime state.
    """

    id: str
    image: Optional[str] = None
    memory: Optional[str] = None
    cpus: Optional[float] = None
    pids: Optional[int] = None
    idle_timeout: Optional[float] = None
    env: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def parse(policy_id: str, raw: Any) -> "Policy":
        if not isinstance(raw, dict):
            raise ConfigError(f"OTPROXY_POLICIES[{policy_id}]: expected an object")
        unknown = set(raw) - {"image", "memory", "cpus", "pids", "idle_timeout", "env"}
        if unknown:
            raise ConfigError(f"OTPROXY_POLICIES[{policy_id}]: unknown keys {sorted(unknown)}")
        env = raw.get("env") or {}
        if not isinstance(env, dict):
            raise ConfigError(f"OTPROXY_POLICIES[{policy_id}].env: expected an object")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", policy_id):
            raise ConfigError(f"OTPROXY_POLICIES: invalid policy id {policy_id!r}")
        return Policy(
            id=policy_id,
            image=raw.get("image"),
            memory=raw.get("memory"),
            cpus=float(raw["cpus"]) if raw.get("cpus") is not None else None,
            pids=int(raw["pids"]) if raw.get("pids") is not None else None,
            idle_timeout=float(raw["idle_timeout"]) if raw.get("idle_timeout") is not None else None,
            env={str(k): str(v) for k, v in env.items()},
        )


@dataclass(frozen=True)
class Settings:
    # --- where we listen -------------------------------------------------
    host: str
    port: int

    # --- who may talk to us ---------------------------------------------
    api_keys: List[str]
    admin_key: str
    metrics_public: bool

    # --- the sandbox image and its shape --------------------------------
    image: str
    pull: str                  # never | missing | always
    container_user: str
    memory_bytes: int
    cpus: float
    pids_limit: int
    nofile: int
    nproc: int
    tmpfs: Dict[str, str]
    storage_size: str
    cap_drop: List[str]
    cap_add: List[str]
    no_new_privileges: bool
    read_only_rootfs: bool
    seccomp_profile: str
    apparmor_profile: str
    runtime: str
    sandbox_env: Dict[str, str]
    persist_home: bool

    # --- networking ------------------------------------------------------
    network_mode: str          # per-user | shared
    supernet: str
    net_prefix: int
    shared_network: str
    upstream_port: int

    # --- lifecycle -------------------------------------------------------
    idle_timeout: float
    max_lifetime: float
    ready_timeout: float
    reap_interval: float
    max_sandboxes: int
    evict_min_idle: float
    pool_size: int
    stop_on_shutdown: bool

    # --- routing ---------------------------------------------------------
    scope_by_context: bool
    policies: Dict[str, Policy]

    # --- proxying --------------------------------------------------------
    request_timeout: float
    connect_timeout: float
    max_body_bytes: int
    schema_ttl: float

    # --- self-checks -----------------------------------------------------
    verify_isolation: bool
    require_isolation: bool
    reject_sandbox_clients: bool

    # --- housekeeping ----------------------------------------------------
    label_namespace: str
    name_prefix: str
    log_level: str
    log_json: bool

    # ----------------------------------------------------------------
    def policy(self, policy_id: Optional[str]) -> Optional[Policy]:
        if not policy_id:
            return None
        return self.policies.get(policy_id)

    def idle_timeout_for(self, policy: Optional[Policy]) -> float:
        if policy is not None and policy.idle_timeout is not None:
            return policy.idle_timeout
        return self.idle_timeout

    def image_for(self, policy: Optional[Policy]) -> str:
        if policy is not None and policy.image:
            return policy.image
        return self.image


def load(environ: Optional[Dict[str, str]] = None) -> Settings:
    """Read and validate the configuration.  Raises :class:`ConfigError`."""
    if environ is not None:                      # tests pass an explicit mapping
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(environ)
        try:
            return load()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    keys = [key for key in ([_str("API_KEY")] + _list("API_KEYS")) if key]
    if not keys:
        raise ConfigError("OTPROXY_API_KEY is required: it is the key Open WebUI sends as its bearer token")
    for key in keys:
        if len(key) < 16:
            raise ConfigError("OTPROXY_API_KEY: use at least 16 characters (this key guards shell access)")

    pull = _str("PULL", "missing").lower()
    if pull not in ("never", "missing", "always"):
        raise ConfigError("OTPROXY_PULL: expected never, missing or always")

    network_mode = _str("NETWORK_MODE", "per-user").lower()
    if network_mode not in ("per-user", "shared"):
        raise ConfigError("OTPROXY_NETWORK_MODE: expected per-user or shared")

    supernet = _str("NET_SUPERNET", "10.88.0.0/16")
    net_prefix = _int("NET_PREFIX", 29, minimum=24, maximum=30)
    try:
        network = ipaddress.ip_network(supernet, strict=True)
    except ValueError as exc:
        raise ConfigError(f"OTPROXY_NET_SUPERNET: {exc}") from None
    if network.version != 4:
        raise ConfigError("OTPROXY_NET_SUPERNET: IPv4 only")
    if net_prefix < network.prefixlen:
        raise ConfigError(
            f"OTPROXY_NET_PREFIX: /{net_prefix} is larger than the supernet /{network.prefixlen}"
        )

    max_sandboxes = _int("MAX_SANDBOXES", 50, minimum=1)
    pool_size = _int("POOL_SIZE", 1, minimum=0)
    if pool_size >= max_sandboxes:
        raise ConfigError(
            f"OTPROXY_POOL_SIZE ({pool_size}) must be smaller than OTPROXY_MAX_SANDBOXES ({max_sandboxes}): "
            "the warm pool would use up every slot"
        )

    log_format = _str("LOG_FORMAT", "text").lower()
    if log_format not in ("text", "json"):
        raise ConfigError("OTPROXY_LOG_FORMAT: expected text or json")

    tmpfs_size = _str("TMPFS_SIZE", "512m")
    parse_size(tmpfs_size, what="OTPROXY_TMPFS_SIZE")
    read_only = _bool("READ_ONLY_ROOTFS", False)
    # A read-only root filesystem needs somewhere to write, or nothing starts.
    tmpfs = {"/tmp": f"size={tmpfs_size},mode=1777,nosuid,nodev"}
    if read_only:
        tmpfs["/run"] = "size=16m,mode=0755,nosuid,nodev"
        tmpfs["/var/tmp"] = f"size={tmpfs_size},mode=1777,nosuid,nodev"

    policies_raw = _json_dict("POLICIES")
    policies = {name: Policy.parse(name, value) for name, value in policies_raw.items()}

    sandbox_env = {str(k): str(v) for k, v in _json_dict("SANDBOX_ENV").items()}
    for name in sandbox_env:
        if name in ("OPEN_TERMINAL_API_KEY", "OPEN_TERMINAL_API_KEY_FILE"):
            raise ConfigError(
                "OTPROXY_SANDBOX_ENV: OPEN_TERMINAL_API_KEY is generated per container and cannot be set"
            )
        if name == "OPEN_TERMINAL_MULTI_USER":
            raise ConfigError(
                "OTPROXY_SANDBOX_ENV: OPEN_TERMINAL_MULTI_USER belongs to the shared-container model; "
                "this proxy gives every user a container instead"
            )

    settings = Settings(
        host=_str("HOST", "0.0.0.0"),
        port=_int("PORT", 8800, minimum=1, maximum=65535),
        api_keys=keys,
        admin_key=_str("ADMIN_KEY"),
        metrics_public=_bool("METRICS_PUBLIC", False),
        image=_str("IMAGE", "ghcr.io/open-webui/open-terminal:latest"),
        pull=pull,
        container_user=_str("SANDBOX_USER"),
        memory_bytes=parse_size(_str("MEMORY", "2g"), what="OTPROXY_MEMORY"),
        cpus=_float("CPUS", 1.0, minimum=0.01),
        pids_limit=_int("PIDS_LIMIT", 512, minimum=16),
        nofile=_int("NOFILE", 4096, minimum=64),
        nproc=_int("NPROC", 512, minimum=16),
        tmpfs=tmpfs,
        storage_size=_str("STORAGE_SIZE"),
        cap_drop=_list("CAP_DROP", "ALL"),
        # SETGID by default: the official full image gives its server binary the
        # cap_setgid file capability, and the kernel refuses to exec such a file
        # when the capability is outside the container's bounding set.  Verified
        # against dockerd 29: without it the sandbox dies with
        # "exec ...: operation not permitted".  Drop it for the slim/alpine images.
        cap_add=_list("CAP_ADD", "SETGID"),
        no_new_privileges=_bool("NO_NEW_PRIVILEGES", True),
        read_only_rootfs=read_only,
        seccomp_profile=_str("SECCOMP_PROFILE"),
        apparmor_profile=_str("APPARMOR_PROFILE"),
        runtime=_str("RUNTIME"),
        sandbox_env=sandbox_env,
        persist_home=_bool("PERSIST_HOME", False),
        network_mode=network_mode,
        supernet=supernet,
        net_prefix=net_prefix,
        shared_network=_str("SHARED_NETWORK", "otproxy-sandboxes"),
        upstream_port=_int("UPSTREAM_PORT", 8000, minimum=1, maximum=65535),
        idle_timeout=_float("IDLE_TIMEOUT", 900.0, minimum=30.0),
        max_lifetime=_float("MAX_LIFETIME", 86400.0, minimum=0.0),
        ready_timeout=_float("READY_TIMEOUT", 90.0, minimum=5.0),
        reap_interval=_float("REAP_INTERVAL", 20.0, minimum=1.0),
        max_sandboxes=max_sandboxes,
        evict_min_idle=_float("EVICT_MIN_IDLE", 60.0, minimum=0.0),
        pool_size=pool_size,
        stop_on_shutdown=_bool("STOP_ON_SHUTDOWN", False),
        scope_by_context=_bool("SCOPE_BY_CONTEXT", True),
        policies=policies,
        request_timeout=_float("REQUEST_TIMEOUT", 300.0, minimum=1.0),
        connect_timeout=_float("CONNECT_TIMEOUT", 5.0, minimum=0.1),
        max_body_bytes=parse_size(_str("MAX_BODY", "1g"), what="OTPROXY_MAX_BODY"),
        schema_ttl=_float("SCHEMA_TTL", 300.0, minimum=0.0),
        verify_isolation=_bool("VERIFY_ISOLATION", True),
        require_isolation=_bool("REQUIRE_ISOLATION", False),
        # A sandbox shares a bridge with the proxy, so it can reach the proxy's
        # own port.  It has no key to use it with, but there is no reason to
        # answer it at all: requests from the sandbox range are refused.
        reject_sandbox_clients=_bool("REJECT_SANDBOX_CLIENTS", True),
        label_namespace=_str("LABEL_NAMESPACE", "sh.openterminal.proxy"),
        name_prefix=_str("NAME_PREFIX", "otsbx"),
        log_level=_str("LOG_LEVEL", "INFO").upper(),
        log_json=log_format == "json",
    )

    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,20}", settings.name_prefix):
        raise ConfigError("OTPROXY_NAME_PREFIX: lowercase letters, digits, '_', '.', '-'; max 21 characters")
    if settings.require_isolation and not settings.verify_isolation:
        raise ConfigError("OTPROXY_REQUIRE_ISOLATION needs OTPROXY_VERIFY_ISOLATION=true")
    if settings.max_lifetime and settings.max_lifetime <= settings.idle_timeout:
        raise ConfigError(
            "OTPROXY_MAX_LIFETIME must be larger than OTPROXY_IDLE_TIMEOUT (or 0 to disable)"
        )
    return settings
