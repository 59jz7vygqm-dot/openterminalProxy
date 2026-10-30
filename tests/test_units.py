"""Unit checks for the parts that decide identity, limits and addresses.

These run in well under a second and need neither Docker nor a socket.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from otproxy import config, ids
from otproxy.dockerapi import demultiplex
from otproxy.netpool import PoolExhausted, SubnetPool
from otproxy.proxy import request_headers, response_headers
from otproxy.sandbox import _key_from_name, _start_failure_hint

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


def raises(name: str, error, function, *args, contains: str = "") -> None:
    try:
        function(*args)
    except error as exc:
        check(name, contains in str(exc), f"message was {str(exc)!r}")
        return
    except Exception as exc:  # noqa: BLE001
        check(name, False, f"raised {type(exc).__name__} instead: {exc}")
        return
    check(name, False, "did not raise")


BASE = {"OTPROXY_API_KEY": "0123456789abcdef-key"}


def test_config() -> None:
    print("\nconfiguration")
    settings = config.load(dict(BASE))
    check("default image is the official one", settings.image.startswith("ghcr.io/open-webui/open-terminal"))
    check("memory default is 2g", settings.memory_bytes == 2 * 1024**3)
    check("SETGID is added back by default", settings.cap_add == ["SETGID"],
          "the official image's server binary carries that file capability")
    check("ALL capabilities dropped", settings.cap_drop == ["ALL"])
    check("per-user networks by default", settings.network_mode == "per-user")
    check("sandbox clients refused by default", settings.reject_sandbox_clients)

    raises("short key rejected", config.ConfigError, config.load, {"OTPROXY_API_KEY": "short"},
           contains="16 characters")
    raises("missing key rejected", config.ConfigError, config.load, {}, contains="OTPROXY_API_KEY is required")
    raises("bad boolean names the variable", config.ConfigError, config.load,
           {**BASE, "OTPROXY_PERSIST_HOME": "maybe"}, contains="OTPROXY_PERSIST_HOME")
    raises("bad size names the variable", config.ConfigError, config.load,
           {**BASE, "OTPROXY_MEMORY": "2 gigs"}, contains="OTPROXY_MEMORY")
    raises("pool cannot fill the ceiling", config.ConfigError, config.load,
           {**BASE, "OTPROXY_POOL_SIZE": "4", "OTPROXY_MAX_SANDBOXES": "4"}, contains="POOL_SIZE")
    raises("lifetime must exceed idle timeout", config.ConfigError, config.load,
           {**BASE, "OTPROXY_MAX_LIFETIME": "60", "OTPROXY_IDLE_TIMEOUT": "900"}, contains="MAX_LIFETIME")
    raises("prefix larger than supernet rejected", config.ConfigError, config.load,
           {**BASE, "OTPROXY_NET_SUPERNET": "10.0.0.0/28", "OTPROXY_NET_PREFIX": "24"}, contains="NET_PREFIX")
    raises("container key cannot be overridden", config.ConfigError, config.load,
           {**BASE, "OTPROXY_SANDBOX_ENV": '{"OPEN_TERMINAL_API_KEY": "x"}'}, contains="generated per container")
    raises("multi-user mode is refused", config.ConfigError, config.load,
           {**BASE, "OTPROXY_SANDBOX_ENV": '{"OPEN_TERMINAL_MULTI_USER": "true"}'}, contains="MULTI_USER")
    raises("isolation requirement needs the check", config.ConfigError, config.load,
           {**BASE, "OTPROXY_REQUIRE_ISOLATION": "true", "OTPROXY_VERIFY_ISOLATION": "false"},
           contains="VERIFY_ISOLATION")

    read_only = config.load({**BASE, "OTPROXY_READ_ONLY_ROOTFS": "true"})
    check("read-only root gets writable /run and /var/tmp",
          set(read_only.tmpfs) == {"/tmp", "/run", "/var/tmp"})
    check("tmpfs is nosuid,nodev", all("nosuid,nodev" in value for value in read_only.tmpfs.values()))

    sized = config.load({**BASE, "OTPROXY_MEMORY": "512m", "OTPROXY_CPUS": "0.5"})
    check("512m parses", sized.memory_bytes == 512 * 1024**2)
    check("fractional cpus parse", sized.cpus == 0.5)

    policies = config.load({**BASE, "OTPROXY_POLICIES": json.dumps(
        {"ds": {"image": "img:1", "memory": "4g", "cpus": 2, "idle_timeout": 60, "env": {"A": "b"}}})})
    check("policy parses", policies.policies["ds"].image == "img:1")
    check("policy image wins", policies.image_for(policies.policies["ds"]) == "img:1")
    check("policy idle timeout wins", policies.idle_timeout_for(policies.policies["ds"]) == 60)
    check("unknown policy is None", policies.policy("nope") is None)
    raises("unknown policy key rejected", config.ConfigError, config.load,
           {**BASE, "OTPROXY_POLICIES": '{"x": {"cpu": 2}}'}, contains="unknown keys")


def test_container_spec() -> None:
    """The hardening is only real if it reaches the container spec."""
    print("\ncontainer spec")
    from otproxy.sandbox import DockerSandboxBackend

    settings = config.load({**BASE, "OTPROXY_MEMORY": "1g", "OTPROXY_CPUS": "2", "OTPROXY_PIDS_LIMIT": "256"})
    backend = DockerSandboxBackend.__new__(DockerSandboxBackend)   # no daemon needed for the spec
    backend.settings = settings
    backend._seccomp_profile = None
    spec = backend._container_spec(
        image="img:1", network="net-1", api_key="container-key", labels={"a": "b"}, policy=None, volume=None
    )
    host = spec["HostConfig"]
    check("memory is capped", host["Memory"] == 1024**3)
    check("swap is pinned to memory, so there is no swap", host["MemorySwap"] == host["Memory"])
    check("cpu quota is set", host["NanoCpus"] == 2_000_000_000)
    check("pids are capped", host["PidsLimit"] == 256)
    check("all capabilities are dropped", host["CapDrop"] == ["ALL"])
    check("no-new-privileges is set", "no-new-privileges:true" in host["SecurityOpt"])
    check("privileged is off", host["Privileged"] is False)
    check("the container is not restarted behind our back", host["RestartPolicy"] == {"Name": ""})
    check("logs are capped", host["LogConfig"]["Config"]["max-size"] == "10m")
    check("ulimits cover files and processes",
          {entry["Name"] for entry in host["Ulimits"]} == {"nofile", "nproc"})
    check("the container joins only its own network", host["NetworkMode"] == "net-1")
    check("the oom killer prefers the sandbox", host["OomScoreAdj"] > 0)
    check("no host mounts by default", "Mounts" not in host)
    environment = dict(item.split("=", 1) for item in spec["Env"])
    check("the container gets its own key", environment["OPEN_TERMINAL_API_KEY"] == "container-key")
    check("in-container multi-user mode stays off", environment["OPEN_TERMINAL_MULTI_USER"] == "false")
    check("no browser origin is allowed", environment["OPEN_TERMINAL_CORS_ALLOWED_ORIGINS"] == "")
    check("the hostname does not leak the container id", spec["Hostname"] == "sandbox")
    check("no egress allow-list is set, the network is the boundary",
          "OPEN_TERMINAL_ALLOWED_DOMAINS" not in environment)

    persistent = config.load({**BASE, "OTPROXY_PERSIST_HOME": "true"})
    backend.settings = persistent
    spec = backend._container_spec(
        image="img:1", network="net-1", api_key="k", labels={}, policy=None, volume="vol-1"
    )
    mounts = spec["HostConfig"]["Mounts"]
    check("a persistent home is a named volume, not a host path", mounts[0]["Type"] == "volume")
    check("the home volume lands on /home/user", mounts[0]["Target"] == "/home/user")

    policy = config.Policy(id="ds", memory="4g", cpus=4.0, pids=1024, env={"X": "1"})
    backend.settings = settings
    spec = backend._container_spec(
        image="img:2", network="net-2", api_key="k", labels={}, policy=policy, volume=None
    )
    check("a policy raises the limits", spec["HostConfig"]["Memory"] == 4 * 1024**3)
    check("a policy sets its own env", dict(item.split("=", 1) for item in spec["Env"])["X"] == "1")


def test_identity() -> None:
    print("\nidentity and keys")
    scope = ids.Scope("user-a")
    other = ids.Scope("user-b")
    check("different users get different keys", scope.key != other.key)
    check("key is stable", ids.Scope("user-a").key == scope.key)
    check("key is 16 hex characters", len(scope.key) == 16 and all(c in "0123456789abcdef" for c in scope.key))
    check("context changes the key", ids.Scope("user-a", "chat:1").key != scope.key)
    check("policy changes the key", ids.Scope("user-a", "", "ds").key != scope.key)
    check("a separator cannot forge another scope",
          ids.Scope("a\x00b").key != ids.Scope("a", "b").key)

    def as_user(value: str):
        return ids.check_id(value, what="X-User-Id")

    raises("empty user id rejected", ids.InvalidIdentity, as_user, "", contains="required")
    raises("a shell metacharacter is rejected", ids.InvalidIdentity, as_user, "user;rm -rf /",
           contains="must be")
    raises("a slash is rejected", ids.InvalidIdentity, as_user, "../../etc", contains="must be")
    raises("an overlong id is rejected", ids.InvalidIdentity, as_user, "a" * 129, contains="must be")
    check("a uuid passes", ids.check_id("9f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", what="x").startswith("9f1c"))

    check("bearer prefix stripped", ids.bearer("Bearer token") == "token")
    check("bare token accepted", ids.bearer("token") == "token")
    check("missing header is empty", ids.bearer(None) == "")
    check("correct key matches", ids.matches_any_key("abcdef0123456789", ["abcdef0123456789"]))
    check("second key matches", ids.matches_any_key("b" * 16, ["a" * 16, "b" * 16]))
    check("wrong key rejected", not ids.matches_any_key("c" * 16, ["a" * 16]))
    check("empty token rejected", not ids.matches_any_key("", ["a" * 16]))
    check("prefix of a key rejected", not ids.matches_any_key("a" * 15, ["a" * 16]))

    names = ids.names("otsbx", scope.key)
    check("names derive from the hash", names.container.endswith(scope.key))
    check("container name recovers the key", _key_from_name(names.container, "otsbx") == scope.key)
    check("a foreign name yields no key", _key_from_name("other-c-abc", "otsbx") == "")


def test_network_pool() -> None:
    print("\nsubnet allocation")
    pool = SubnetPool("10.88.0.0/16", 29)
    check("a /16 yields 8192 /29 blocks", pool.capacity == 8192)
    first = pool.allocate([])
    check("first block is the lowest", first == "10.88.0.0/29")
    check("an allocated block is skipped", pool.allocate([first]) == "10.88.0.8/29")
    check("an overlapping /24 is skipped", pool.allocate(["10.88.0.0/24"]) == "10.88.1.0/29")
    check("a foreign network does not block us", pool.allocate(["172.17.0.0/16"]) == "10.88.0.0/29")
    check("malformed entries are ignored", pool.allocate(["not-a-network"]) == "10.88.0.0/29")
    check("gateway is the first host", SubnetPool.gateway("10.88.0.8/29") == "10.88.0.9")

    tiny = SubnetPool("10.0.0.0/30", 30)
    check("a single-block pool allocates once", tiny.allocate([]) == "10.0.0.0/30")
    raises("an exhausted pool says so", PoolExhausted, tiny.allocate, ["10.0.0.0/30"], contains="fully allocated")


def test_header_handling() -> None:
    print("\nheader handling")
    incoming = [
        ("host", "proxy:8800"),
        ("authorization", "Bearer the-open-webui-key"),
        ("connection", "keep-alive"),
        ("transfer-encoding", "chunked"),
        ("content-length", "12"),
        ("x-user-id", "user-a"),
        ("x-session-id", "chat-1"),
        ("x-terminal-context-id", "chat:1"),
        ("content-type", "application/json"),
    ]
    forwarded = {name.decode(): value.decode() for name, value in request_headers(incoming, "container-key")}
    check("the caller's key never reaches the container",
          forwarded["authorization"] == "Bearer container-key")
    check("host is not forwarded", "host" not in forwarded)
    check("hop-by-hop headers are dropped",
          not {"connection", "transfer-encoding"} & set(forwarded))
    check("content-length is recomputed", "content-length" not in forwarded)
    check("the user id is forwarded", forwarded["x-user-id"] == "user-a")
    check("the session id is forwarded", forwarded["x-session-id"] == "chat-1")
    check("the terminal context is forwarded", forwarded["x-terminal-context-id"] == "chat:1")
    check("content type survives", forwarded["content-type"] == "application/json")

    returned = response_headers(
        [("content-type", "application/json"), ("content-length", "5"), ("content-encoding", "gzip"),
         ("server", "uvicorn"), ("date", "now"), ("connection", "close")]
    )
    check("content-length is preserved on the way back", returned["content-length"] == "5")
    check("content-encoding is preserved", returned["content-encoding"] == "gzip")
    check("upstream server/date are dropped", not {"server", "date"} & set(returned))


def test_docker_stream_framing() -> None:
    print("\ndocker stream framing")
    framed = b"\x01\x00\x00\x00\x00\x00\x00\x05hello" + b"\x02\x00\x00\x00\x00\x00\x00\x06 world"
    check("stdout and stderr are interleaved in order", demultiplex(framed) == b"hello world")
    check("an unframed body is returned as-is", demultiplex(b"plain text") == b"plain text")
    check("a truncated frame does not raise", demultiplex(b"\x01\x00\x00\x00\x00\x00\x00\x09short") == b"short")
    check("an empty body stays empty", demultiplex(b"") == b"")


def test_failure_hints() -> None:
    print("\nstartup failure hints")
    settings = config.load(dict(BASE))
    capability = _start_failure_hint(
        "failed to create task: exec /usr/local/bin/open-terminal: operation not permitted", "", settings
    )
    check("the file-capability failure explains itself", "OTPROXY_CAP_ADD=SETGID" in capability)
    quota = _start_failure_hint("--storage-opt is supported only for overlay over xfs", "", settings)
    check("the storage quota failure explains itself", "pquota" in quota)
    plain = _start_failure_hint("boom", "log line", settings)
    check("the container log is included", "log line" in plain)


def main() -> int:
    test_config()
    test_container_spec()
    test_identity()
    test_network_pool()
    test_header_handling()
    test_docker_stream_framing()
    test_failure_hints()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
