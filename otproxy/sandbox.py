"""Creating, finding and destroying the containers themselves.

Everything Docker-specific lives here.  The manager above it only deals in
:class:`Sandbox` records, which is what makes it testable without a daemon.

The shape of a sandbox, and why:

* **No route off the box.**  Each sandbox sits on a bridge network created with
  ``Internal: true``, so the kernel has no route from it to anything but that
  bridge -- a connect to the internet fails with ENETUNREACH before a packet is
  sent.  There is nothing to misconfigure at the application level and nothing
  for a user to turn off from inside.
* **One network per user** (the default).  An internal network still carries
  traffic *within* itself, so a single shared one would let one user's shell
  reach another user's terminal API.  A network of its own, holding only that
  sandbox and the proxy, removes the question.
* **No capabilities, no privilege escalation.**  ``CapDrop: [ALL]`` plus
  ``no-new-privileges`` means the passwordless ``sudo`` the official image ships
  with cannot be used.  CAP_SETGID is added back by default because the image's
  server binary carries that file capability and the kernel refuses to exec such
  a binary when the capability is outside the bounding set.
* **Bounded.**  Memory without swap, a CPU quota, a pid limit, file-descriptor
  and process ulimits, a size-capped tmpfs on /tmp, and a capped json-file log.
  A fork bomb or a runaway allocation takes the sandbox down, not the host.
* **Its own credential.**  Every container gets a freshly generated API key, so
  the key Open WebUI holds is never the key that reaches a container, and one
  container's key is worthless against another.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import log
from .config import Policy, Settings
from .dockerapi import DockerClient, DockerError
from .ids import Names, Scope, names
from .netpool import SubnetPool

logger = log.get("sandbox")

ROLE_SANDBOX = "sandbox"
ROLE_WARM = "warm"


@dataclass
class Sandbox:
    """One running Open Terminal container, owned by one scope."""

    key: str
    name: str
    container_id: str
    api_key: str
    ip: str
    port: int
    network: str
    scope: Optional[Scope] = None
    policy_id: str = ""
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    ready: bool = False
    requests: int = 0

    @property
    def base_url(self) -> str:
        return f"http://{self.ip}:{self.port}"

    def touch(self) -> None:
        self.last_used = time.time()
        self.requests += 1

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_used

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created

    def public(self) -> Dict[str, Any]:
        """What the admin API reports.  No keys, no IPs of other sandboxes."""
        return {
            "key": self.key,
            "name": self.name,
            "user_id": self.scope.user_id if self.scope else None,
            "context_id": self.scope.context_id if self.scope else None,
            "policy": self.policy_id or None,
            "network": self.network,
            "ready": self.ready,
            "requests": self.requests,
            "age_seconds": round(self.age_seconds, 1),
            "idle_seconds": round(self.idle_seconds, 1),
        }


class SandboxError(RuntimeError):
    """Creating or reaching a sandbox failed.  The message is operator-facing."""


class DockerSandboxBackend:
    """The Docker implementation of the few operations the manager needs."""

    def __init__(self, settings: Settings, client: Optional[DockerClient] = None) -> None:
        self.settings = settings
        self.docker = client or DockerClient()
        self.pool = SubnetPool(settings.supernet, settings.net_prefix)
        self._self_container: Optional[str] = None
        self._self_resolved = False
        self._seccomp_profile: Optional[str] = None
        self._image_ready: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # labels
    # ------------------------------------------------------------------

    @property
    def _ns(self) -> str:
        return self.settings.label_namespace

    @property
    def owner_label(self) -> str:
        return f"{self._ns}/owned=true"

    def _labels(self, *, role: str, scope: Optional[Scope], policy_id: str) -> Dict[str, str]:
        labels = {
            f"{self._ns}/owned": "true",
            f"{self._ns}/role": role,
            f"{self._ns}/created": str(int(time.time())),
        }
        if scope is not None:
            labels[f"{self._ns}/key"] = scope.key
            labels[f"{self._ns}/user"] = scope.user_id
            if scope.context_id:
                labels[f"{self._ns}/context"] = scope.context_id
        if policy_id:
            labels[f"{self._ns}/policy"] = policy_id
        return labels

    def _label_value(self, container: Dict[str, Any], suffix: str) -> str:
        return (container.get("Labels") or {}).get(f"{self._ns}/{suffix}", "")

    # ------------------------------------------------------------------
    # the proxy's own container
    # ------------------------------------------------------------------

    async def resolve_self(self) -> Optional[str]:
        """Return the proxy's own container id, or None when it runs on the host.

        A containerised proxy has to join each sandbox network to be able to
        reach it; a proxy on the host reaches the bridge directly and must not
        try.  Detection order: an explicit setting, the hostname (which Docker
        sets to the short container id unless told otherwise), then the
        container id in /proc/self/mountinfo.
        """
        if self._self_resolved:
            return self._self_container
        self._self_resolved = True
        explicit = os.environ.get("OTPROXY_SELF_CONTAINER", "").strip()
        candidates = [explicit] if explicit else []
        hostname = os.environ.get("HOSTNAME", "").strip()
        if hostname:
            candidates.append(hostname)
        candidates.extend(_container_ids_from_mountinfo())
        for candidate in candidates:
            if not candidate:
                continue
            try:
                info = await self.docker.inspect_container(candidate)
            except DockerError:
                info = None
            if info:
                self._self_container = info["Id"]
                logger.info("running inside container %s", info["Id"][:12])
                return self._self_container
        if explicit:
            raise SandboxError(
                f"OTPROXY_SELF_CONTAINER={explicit!r} is not a container this daemon knows"
            )
        logger.info("not running inside a container: sandbox networks are reached through the host bridge")
        return None

    # ------------------------------------------------------------------
    # images
    # ------------------------------------------------------------------

    async def ensure_image(self, image: str) -> None:
        if self.settings.pull == "always":
            logger.info("pulling %s", image)
            await self.docker.pull(image)
            self._image_ready[image] = True
            return
        if self._image_ready.get(image):
            return
        if await self.docker.image_exists(image):
            self._image_ready[image] = True
            return
        if self.settings.pull == "never":
            raise SandboxError(
                f"image {image} is not present and OTPROXY_PULL=never; pull it first: docker pull {image}"
            )
        logger.info("image %s is missing, pulling it once", image)
        await self.docker.pull(image)
        self._image_ready[image] = True

    # ------------------------------------------------------------------
    # networks
    # ------------------------------------------------------------------

    async def ensure_network(self, scope: Optional[Scope], name: str, policy_id: str = "") -> str:
        """Create the sandbox network if it is missing, and join it ourselves."""
        existing = await self.docker.inspect_network(name)
        if existing is None:
            taken = [
                config.get("Subnet", "")
                for network in await self.docker.list_networks()
                for config in ((network.get("IPAM") or {}).get("Config") or [])
                if config.get("Subnet")
            ]
            subnet = self.pool.allocate(taken)
            spec = {
                "Driver": "bridge",
                "Internal": True,          # the whole point: no route off the bridge
                "EnableIPv6": False,
                "Attachable": False,
                "CheckDuplicate": True,
                "IPAM": {"Driver": "default", "Config": [{"Subnet": subnet}]},
                "Options": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
                "Labels": self._labels(role="network", scope=scope, policy_id=policy_id),
            }
            try:
                await self.docker.create_network(name, spec)
                logger.info("created network %s (%s, internal)", name, subnet)
            except DockerError as exc:
                # Another replica, or a racing request, got there first.
                if not (exc.is_conflict or "already exists" in exc.message):
                    raise
        self_container = await self.resolve_self()
        if self_container:
            await self.docker.connect_network(name, self_container)
        return name

    async def network_gateway(self, name: str) -> Optional[str]:
        network = await self.docker.inspect_network(name)
        if not network:
            return None
        for config in (network.get("IPAM") or {}).get("Config") or []:
            if config.get("Gateway"):
                return str(config["Gateway"])
            if config.get("Subnet"):
                return SubnetPool.gateway(str(config["Subnet"]))
        return None

    async def remove_network(self, name: str) -> None:
        self_container = await self.resolve_self()
        if self_container:
            await self.docker.disconnect_network(name, self_container)
        await self.docker.remove_network(name)

    # ------------------------------------------------------------------
    # containers
    # ------------------------------------------------------------------

    def _container_spec(
        self,
        *,
        image: str,
        network: str,
        api_key: str,
        labels: Dict[str, str],
        policy: Optional[Policy],
        volume: Optional[str],
    ) -> Dict[str, Any]:
        settings = self.settings
        memory = settings.memory_bytes
        if policy is not None and policy.memory:
            from .config import parse_size

            memory = parse_size(policy.memory, what=f"policy {policy.id} memory")
        cpus = policy.cpus if (policy is not None and policy.cpus) else settings.cpus
        pids = policy.pids if (policy is not None and policy.pids) else settings.pids_limit

        environment = {
            # Per container, so a leaked key is worth nothing elsewhere.  The
            # server strips OPEN_TERMINAL_* from the environment of the commands
            # it runs, so this does not land in the user's shell.
            "OPEN_TERMINAL_API_KEY": api_key,
            # Nothing but this proxy talks to the container, so no browser origin
            # needs to be allowed.
            "OPEN_TERMINAL_CORS_ALLOWED_ORIGINS": "",
            # One container per user is the isolation; the in-container user
            # split is explicitly not a security boundary.
            "OPEN_TERMINAL_MULTI_USER": "false",
        }
        environment.update(settings.sandbox_env)
        if policy is not None:
            environment.update(policy.env)

        security_opt: List[str] = []
        if settings.no_new_privileges:
            security_opt.append("no-new-privileges:true")
        if settings.seccomp_profile:
            security_opt.append(f"seccomp={self._load_seccomp()}")
        if settings.apparmor_profile:
            security_opt.append(f"apparmor={settings.apparmor_profile}")

        host_config: Dict[str, Any] = {
            "NetworkMode": network,
            "Memory": memory,
            "MemorySwap": memory,            # equal to Memory means: no swap
            "MemorySwappiness": 0,
            "NanoCpus": int(cpus * 1_000_000_000),
            "PidsLimit": pids,
            "CapDrop": settings.cap_drop,
            "CapAdd": settings.cap_add,
            "Privileged": False,
            "ReadonlyRootfs": settings.read_only_rootfs,
            "Tmpfs": dict(settings.tmpfs),
            "Ulimits": [
                {"Name": "nofile", "Soft": settings.nofile, "Hard": settings.nofile},
                {"Name": "nproc", "Soft": settings.nproc, "Hard": settings.nproc},
            ],
            "RestartPolicy": {"Name": ""},   # the reaper decides, not the daemon
            "AutoRemove": False,             # keep the logs of a crash
            "OomScoreAdj": 500,              # the host kills a sandbox before itself
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "2"}},
        }
        if security_opt:
            host_config["SecurityOpt"] = security_opt
        if settings.runtime:
            host_config["Runtime"] = settings.runtime
        if settings.storage_size:
            # Only honoured by storage drivers that support quotas; the daemon
            # rejects it otherwise, which the caller turns into a clear error.
            host_config["StorageOpt"] = {"size": settings.storage_size}
        if volume:
            host_config["Mounts"] = [
                {"Type": "volume", "Source": volume, "Target": "/home/user", "ReadOnly": False}
            ]

        spec: Dict[str, Any] = {
            "Image": image,
            # A fixed hostname: the default leaks the container id into the
            # user's shell prompt, and nothing depends on it.
            "Hostname": "sandbox",
            "Env": [f"{key}={value}" for key, value in environment.items()],
            "Labels": labels,
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "OpenStdin": False,
            "Tty": False,
            "HostConfig": host_config,
            "NetworkingConfig": {"EndpointsConfig": {network: {}}} if network != "none" else {},
        }
        if self.settings.container_user:
            spec["User"] = self.settings.container_user
        return spec

    def _load_seccomp(self) -> str:
        """Read the seccomp profile once; the API takes the JSON, not a path."""
        if self._seccomp_profile is None:
            path = self.settings.seccomp_profile
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    profile = json.load(handle)
            except (OSError, ValueError) as exc:
                raise SandboxError(f"OTPROXY_SECCOMP_PROFILE {path}: {exc}") from None
            self._seccomp_profile = json.dumps(profile, separators=(",", ":"))
        return self._seccomp_profile

    async def create(
        self,
        *,
        scope: Optional[Scope],
        policy: Optional[Policy],
        role: str = ROLE_SANDBOX,
        name: Optional[str] = None,
        network: Optional[str] = None,
    ) -> Sandbox:
        """Create and start a container.  Does not wait for it to be ready."""
        settings = self.settings
        policy_id = policy.id if policy else ""
        image = settings.image_for(policy)
        await self.ensure_image(image)

        if scope is not None:
            sandbox_names = names(settings.name_prefix, scope.key)
        else:
            sandbox_names = Names(
                container=name or f"{settings.name_prefix}-w-{secrets.token_hex(6)}",
                network=network or "none",
                volume="",
            )
        container_name = name or sandbox_names.container
        network_name = network or (
            sandbox_names.network if settings.network_mode == "per-user" else settings.shared_network
        )
        if network_name != "none":
            await self.ensure_network(scope, network_name, policy_id)

        volume = None
        if settings.persist_home and scope is not None:
            volume = sandbox_names.volume
            await self.docker.create_volume(volume, self._labels(role=role, scope=scope, policy_id=policy_id))

        api_key = secrets.token_urlsafe(32)
        spec = self._container_spec(
            image=image,
            network=network_name,
            api_key=api_key,
            labels=self._labels(role=role, scope=scope, policy_id=policy_id),
            policy=policy,
            volume=volume,
        )

        try:
            container_id = await self.docker.create_container(container_name, spec)
        except DockerError as exc:
            if exc.is_conflict:
                # Someone else created it between our lookup and now: adopt it.
                existing = await self.adopt(container_name)
                if existing is not None:
                    return existing
            raise SandboxError(f"could not create {container_name}: {exc.message}") from None

        try:
            await self.docker.start_container(container_id)
        except DockerError as exc:
            tail = await self.docker.container_logs(container_id, tail=20)
            await self.docker.remove_container(container_id)
            raise SandboxError(_start_failure_hint(exc.message, tail, settings)) from None

        ip = await self.container_ip(container_id, network_name)
        return Sandbox(
            key=scope.key if scope else container_name,
            name=container_name,
            container_id=container_id,
            api_key=api_key,
            ip=ip or "",
            port=settings.upstream_port,
            network=network_name,
            scope=scope,
            policy_id=policy_id,
        )

    async def container_ip(self, container: str, network: str) -> Optional[str]:
        info = await self.docker.inspect_container(container)
        if not info:
            return None
        networks = ((info.get("NetworkSettings") or {}).get("Networks") or {})
        endpoint = networks.get(network)
        if endpoint and endpoint.get("IPAddress"):
            return str(endpoint["IPAddress"])
        for endpoint in networks.values():            # single-network containers
            if endpoint.get("IPAddress"):
                return str(endpoint["IPAddress"])
        return None

    async def claim_warm(self, warm: Sandbox, scope: Scope, policy: Optional[Policy]) -> Sandbox:
        """Hand a pre-started container to a user.

        The container is attached to the user's network, taken off whatever it
        was on, and renamed to the scope's name so that a restarted proxy finds
        it again.
        """
        settings = self.settings
        sandbox_names = names(settings.name_prefix, scope.key)
        network_name = (
            sandbox_names.network if settings.network_mode == "per-user" else settings.shared_network
        )
        await self.ensure_network(scope, network_name, policy.id if policy else "")
        try:
            # The daemon refuses to add a second network while the container is
            # in private ("none") mode, so that endpoint goes first.  Verified
            # against dockerd 29: disconnecting and connecting a running
            # container works, and the server picks up the new address.
            if warm.network == "none":
                await self.docker.disconnect_network("none", warm.container_id)
            await self.docker.connect_network(network_name, warm.container_id)
            if warm.network not in ("none", network_name):
                await self.docker.disconnect_network(warm.network, warm.container_id)
            await self.docker.rename_container(warm.container_id, sandbox_names.container)
            ip = await self.container_ip(warm.container_id, network_name)
            if not ip:
                raise SandboxError(f"warm container {warm.container_id[:12]} has no address on {network_name}")
        except (DockerError, SandboxError) as exc:
            # A half-attached container is of no use to anyone: drop it rather
            # than hand out something that may be on the wrong network.
            await self.docker.remove_container(warm.container_id, force=True, volumes=True)
            raise SandboxError(f"could not hand a warm container to {scope.describe()}: {exc}") from None
        warm.key = scope.key
        warm.name = sandbox_names.container
        warm.network = network_name
        warm.ip = ip
        warm.scope = scope
        warm.policy_id = policy.id if policy else ""
        warm.ready = False
        return warm

    async def destroy(self, sandbox: Sandbox) -> None:
        """Remove the container, its network and (if ephemeral) its volume."""
        await self.docker.remove_container(sandbox.container_id, force=True, volumes=True)
        if self.settings.network_mode == "per-user" and sandbox.network not in ("none", self.settings.shared_network):
            try:
                await self.remove_network(sandbox.network)
            except DockerError as exc:
                logger.warning("network %s stayed behind: %s", sandbox.network, exc.message)
        if not self.settings.persist_home and sandbox.scope is not None:
            volume = names(self.settings.name_prefix, sandbox.scope.key).volume
            await self.docker.remove_volume(volume)

    # ------------------------------------------------------------------
    # discovery after a restart
    # ------------------------------------------------------------------

    async def adopt(self, container_name: str) -> Optional[Sandbox]:
        info = await self.docker.inspect_container(container_name)
        if not info:
            return None
        return await self._sandbox_from_inspect(info)

    async def adopt_all(self) -> Tuple[List[Sandbox], List[Sandbox]]:
        """Find the sandboxes and warm containers a previous run left behind.

        A proxy restart must not orphan a user's shell: the containers are the
        state, the process only holds a cache of it.
        """
        sandboxes: List[Sandbox] = []
        warm: List[Sandbox] = []
        for entry in await self.docker.list_containers(label=self.owner_label, all_states=True):
            name = (entry.get("Names") or ["/?"])[0].lstrip("/")
            role = self._label_value(entry, "role")
            if entry.get("State") != "running":
                logger.info("removing leftover %s container %s (state=%s)", role or "?", name, entry.get("State"))
                await self.docker.remove_container(entry["Id"])
                continue
            info = await self.docker.inspect_container(entry["Id"])
            if not info:
                continue
            adopted = await self._sandbox_from_inspect(info)
            if adopted is None:
                continue
            if role == ROLE_WARM:
                warm.append(adopted)
            else:
                sandboxes.append(adopted)
        return sandboxes, warm

    async def _sandbox_from_inspect(self, info: Dict[str, Any]) -> Optional[Sandbox]:
        labels = (info.get("Config") or {}).get("Labels") or {}
        name = (info.get("Name") or "").lstrip("/")
        environment = {}
        for item in (info.get("Config") or {}).get("Env") or []:
            key, _, value = item.partition("=")
            environment[key] = value
        api_key = environment.get("OPEN_TERMINAL_API_KEY", "")
        networks = ((info.get("NetworkSettings") or {}).get("Networks") or {})
        network, ip = "none", ""
        for candidate, endpoint in networks.items():
            if endpoint.get("IPAddress"):
                network, ip = candidate, str(endpoint["IPAddress"])
                break
        key = labels.get(f"{self._ns}/key") or _key_from_name(name, self.settings.name_prefix) or name
        user_id = labels.get(f"{self._ns}/user", "")
        context_id = labels.get(f"{self._ns}/context", "")
        policy_id = labels.get(f"{self._ns}/policy", "")
        scope = Scope(user_id, context_id, policy_id) if user_id else None
        # A scope rebuilt from labels must still hash to the name we found it
        # under; if it does not, the labels are stale and the name wins.
        if scope is not None and scope.key != key:
            scope = None
        created = _parse_created(info.get("Created"))
        sandbox = Sandbox(
            key=key,
            name=name,
            container_id=info["Id"],
            api_key=api_key,
            ip=ip,
            port=self.settings.upstream_port,
            network=network,
            scope=scope,
            policy_id=policy_id,
            created=created,
            last_used=time.time(),
        )
        if not api_key or not ip:
            logger.warning("container %s is unusable (no key or no address), removing it", name)
            await self.docker.remove_container(info["Id"])
            return None
        return sandbox

    async def prune_networks(self, keep: List[str]) -> int:
        """Remove our networks that no longer hold a sandbox."""
        removed = 0
        for network in await self.docker.list_networks(label=self.owner_label):
            name = network.get("Name", "")
            if not name or name in keep or name == self.settings.shared_network:
                continue
            detail = await self.docker.inspect_network(name)
            if detail is None:
                continue
            attached = detail.get("Containers") or {}
            self_container = await self.resolve_self()
            others = [cid for cid in attached if cid != self_container]
            if others:
                continue
            try:
                await self.remove_network(name)
                removed += 1
            except DockerError as exc:
                logger.debug("could not remove network %s: %s", name, exc.message)
        return removed

    async def prune_volumes(self, keep: List[str]) -> int:
        if self.settings.persist_home:
            return 0            # persistent homes outlive their container on purpose
        removed = 0
        for volume in await self.docker.list_volumes(label=self.owner_label):
            name = volume.get("Name", "")
            if not name or name in keep:
                continue
            try:
                await self.docker.remove_volume(name)
                removed += 1
            except DockerError:
                pass            # still attached; the next sweep will get it
        return removed


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _key_from_name(name: str, prefix: str) -> str:
    match = re.fullmatch(rf"{re.escape(prefix)}-c-([0-9a-f]{{16}})", name)
    return match.group(1) if match else ""


def _parse_created(value: Optional[str]) -> float:
    if not value:
        return time.time()
    text = value.split(".")[0].rstrip("Z")
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except ValueError:
        return time.time()


def _container_ids_from_mountinfo() -> List[str]:
    """Pull container ids out of /proc/self/mountinfo.

    Works where cgroup v2 hides the id: the overlay mounts still reference
    /var/lib/docker/containers/<id>/.
    """
    found: List[str] = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return found
    for match in re.finditer(r"/containers/([0-9a-f]{64})/", text):
        if match.group(1) not in found:
            found.append(match.group(1))
    return found


def _start_failure_hint(message: str, log_tail: str, settings: Settings) -> str:
    """Turn the two failures people actually hit into an answer, not a riddle."""
    combined = f"{message} {log_tail}".lower()
    hint = ""
    if "operation not permitted" in combined and "exec" in combined:
        hint = (
            "  This is the image's file capability meeting an empty capability bounding set. "
            "Set OTPROXY_CAP_ADD=SETGID (the default) for the full image, or "
            "OTPROXY_CAP_ADD=SETGID,SETUID plus OTPROXY_SANDBOX_USER=1000:1000 for the slim/alpine images."
        )
    elif "storage-opt" in combined or "storage opt" in combined:
        hint = (
            "  OTPROXY_STORAGE_SIZE needs a storage driver with quota support "
            "(overlay2 on XFS with pquota). Unset it to start without a writable-layer cap."
        )
    elif "runtime" in combined and "not found" in combined:
        hint = f"  OTPROXY_RUNTIME={settings.runtime!r} is not registered with this daemon."
    return f"sandbox failed to start: {message}" + (f"\n  container log: {log_tail}" if log_tail else "") + hint
