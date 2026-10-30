"""Checks against a real Docker daemon: the parts no fake can prove.

What is actually verified here:

* a sandbox starts, becomes ready and answers through the proxy;
* its own key is enforced -- another key gets a 401 from the container;
* the hardening reached the daemon (capabilities, pid limit, memory, network);
* **there is no route to the internet** from inside a sandbox;
* **one user's sandbox cannot reach another's** with per-user networks -- and
  can with a shared one, which is why per-user is the default;
* the host is reachable from a sandbox until scripts/sandbox-host-firewall.sh
  is installed, and is not afterwards;
* a restarted proxy adopts running sandboxes instead of orphaning them;
* idle sandboxes and their networks are reaped.

It needs a reachable Docker daemon, gcc and the docker CLI (for ``docker
import``).  Without them it prints why it is skipping and exits 0, so it can sit
in the same suite as everything else.

Everything it creates carries the label namespace below and is removed at the
end, including after a failure.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx

from otproxy import config
from otproxy.dockerapi import DockerClient
from otproxy.ids import Scope
from otproxy.manager import CapacityError, SandboxManager
from otproxy.sandbox import DockerSandboxBackend

IMAGE = "otproxy-fake-terminal:test"
SUPERNET = "10.99.0.0/16"
NAMESPACE = "sh.openterminal.proxy.test"
PREFIX = "otsbxtest"
KEY = "0123456789abcdef-docker"
HERE = os.path.dirname(os.path.abspath(__file__))

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


def skip(reason: str) -> int:
    print(f"  skipped: {reason}")
    print("\n0 passed, 0 failed (skipped)")
    return 0


def build_image() -> None:
    """Compile the stand-in server and import it as a scratch image."""
    with tempfile.TemporaryDirectory() as workspace:
        root = os.path.join(workspace, "root", "bin")
        os.makedirs(root)
        subprocess.run(
            ["gcc", "-static", "-O2", "-o", os.path.join(root, "fakeot"),
             os.path.join(HERE, "fake_terminal.c")],
            check=True, capture_output=True,
        )
        archive = os.path.join(workspace, "image.tar")
        subprocess.run(["tar", "-C", os.path.join(workspace, "root"), "-cf", archive, "."], check=True)
        subprocess.run(
            ["docker", "import", "--change", 'ENTRYPOINT ["/bin/fakeot"]',
             "--change", "EXPOSE 8000", archive, IMAGE],
            check=True, capture_output=True,
        )


def settings_for(**extra: str) -> config.Settings:
    return config.load({
        "OTPROXY_API_KEY": KEY,
        "OTPROXY_IMAGE": IMAGE,
        "OTPROXY_PULL": "never",
        "OTPROXY_CAP_ADD": "",              # the stand-in carries no file capability
        "OTPROXY_NET_SUPERNET": SUPERNET,
        "OTPROXY_LABEL_NAMESPACE": NAMESPACE,
        "OTPROXY_NAME_PREFIX": PREFIX,
        "OTPROXY_POOL_SIZE": "0",
        "OTPROXY_MAX_SANDBOXES": "4",
        "OTPROXY_READY_TIMEOUT": "60",
        "OTPROXY_MEMORY": "256m",
        "OTPROXY_PIDS_LIMIT": "64",
        "OTPROXY_VERIFY_ISOLATION": "false",  # probed below with our own binary
        "OTPROXY_LOG_LEVEL": "WARNING",
        **extra,
    })


async def probe_from(manager: SandboxManager, container: str, *targets: tuple) -> str:
    arguments = []
    for host, port in targets:
        arguments += [str(host), str(port)]
    result = await manager.backend.docker.exec_run(container, ["/bin/fakeot", *arguments], timeout=30)
    return result.output


async def cleanup(client: DockerClient) -> None:
    for container in await client.list_containers(label=f"{NAMESPACE}/owned=true", all_states=True):
        await client.remove_container(container["Id"])
    for network in await client.list_networks(label=f"{NAMESPACE}/owned=true"):
        await client.remove_network(network["Name"])
    for volume in await client.list_volumes(label=f"{NAMESPACE}/owned=true"):
        await client.remove_volume(volume["Name"])


def firewall(action: str) -> bool:
    script = os.path.join(HERE, "..", "scripts", "sandbox-host-firewall.sh")
    result = subprocess.run([script, action, SUPERNET], capture_output=True, text=True)
    return result.returncode == 0


async def main() -> int:
    print("\ndocker integration")
    if not shutil.which("docker") or not shutil.which("gcc") or not shutil.which("tar"):
        return skip("needs the docker CLI, gcc and tar")
    client = DockerClient()
    try:
        if not await client.ping():
            return skip("no Docker daemon answered")
    except Exception as exc:  # noqa: BLE001
        return skip(f"no Docker daemon reachable: {exc}")

    try:
        build_image()
    except subprocess.CalledProcessError as exc:
        return skip(f"could not build the test image: {exc.stderr[:200] if exc.stderr else exc}")

    await cleanup(client)
    settings = settings_for()
    manager = SandboxManager(settings, DockerSandboxBackend(settings, client))
    probe = httpx.AsyncClient(timeout=10.0, trust_env=False)
    try:
        await manager.start()

        # --- a sandbox starts and answers -------------------------------
        alice = await manager.acquire(Scope("alice"))
        check("a sandbox starts and reports ready", alice.ready)
        response = await probe.get(f"{alice.base_url}/health")
        check("the container answers its health endpoint", response.json()["status"] == "ok")
        response = await probe.get(f"{alice.base_url}/execute",
                                  headers={"Authorization": f"Bearer {alice.api_key}"})
        check("its own key is accepted", response.status_code == 200)
        response = await probe.get(f"{alice.base_url}/execute",
                                  headers={"Authorization": f"Bearer {KEY}"})
        check("the Open WebUI key is not accepted by the container", response.status_code == 401,
              "the container must only accept the key the proxy generated for it")

        # --- the hardening reached the daemon ---------------------------
        info = await client.inspect_container(alice.container_id)
        host_config = info["HostConfig"]
        check("all capabilities dropped", host_config["CapDrop"] == ["ALL"])
        check("no capability added back in this configuration", not host_config.get("CapAdd"))
        check("no-new-privileges set", "no-new-privileges:true" in (host_config.get("SecurityOpt") or []))
        check("memory capped at 256m", host_config["Memory"] == 256 * 1024**2)
        check("swap disabled", host_config["MemorySwap"] == host_config["Memory"])
        check("pids capped", host_config["PidsLimit"] == 64)
        check("not privileged", host_config["Privileged"] is False)
        ports = info["NetworkSettings"].get("Ports") or {}
        # An EXPOSE in the image shows up here with a null binding; what must not
        # exist is a binding, which would put the terminal API on the host.
        check("no port is published to the host", all(not binding for binding in ports.values()),
              f"published: { {port: binding for port, binding in ports.items() if binding} }")
        check("joined only its own network", list(info["NetworkSettings"]["Networks"]) == [alice.network])

        network = await client.inspect_network(alice.network)
        check("the sandbox network is internal", network["Internal"] is True)
        subnet = (network["IPAM"]["Config"] or [{}])[0].get("Subnet", "")
        check("its subnet comes from the configured supernet", subnet.startswith("10.99."), subnet)

        # --- no route to the internet -----------------------------------
        output = await probe_from(manager, alice.container_id, ("1.1.1.1", 443), ("8.8.8.8", 53))
        check("the sandbox cannot reach the internet", "REACHABLE" not in output, output.strip())
        check("the failure is a missing route, not a refusal",
              "unreachable" in output.lower(), output.strip())

        # --- one user cannot reach another ------------------------------
        bob = await manager.acquire(Scope("bob"))
        check("a second user gets a second sandbox", bob.container_id != alice.container_id)
        check("and a network of their own", bob.network != alice.network)
        output = await probe_from(manager, alice.container_id, (bob.ip, settings.upstream_port))
        check("one sandbox cannot reach another user's sandbox", "REACHABLE" not in output, output.strip())

        # --- the host is reachable until the firewall rule is in place ---
        gateway = await manager.backend.network_gateway(alice.network)
        output = await probe_from(manager, alice.container_id, (gateway, 9))
        host_reachable = "Connection refused" in output or "REACHABLE" in output
        check("docker alone does not keep a sandbox away from the host", host_reachable,
              f"expected the host to answer at {gateway}: {output.strip()}")
        if os.geteuid() == 0 and firewall("install"):
            output = await probe_from(manager, alice.container_id, (gateway, 9))
            check("after sandbox-host-firewall.sh the host is unreachable",
                  "Connection refused" not in output and "REACHABLE" not in output, output.strip())
            response = await probe.get(f"{alice.base_url}/health")
            check("the proxy can still reach the sandbox with the rule installed",
                  response.status_code == 200)
            firewall("remove")
        else:
            print("  note: skipping the firewall check (needs root and iptables)")

        # --- a restarted proxy adopts what is running --------------------
        second = SandboxManager(settings, DockerSandboxBackend(settings, DockerClient()))
        await second.start()
        try:
            adopted = await second.acquire(Scope("alice"))
            check("a restarted proxy adopts the running sandbox",
                  adopted.container_id == alice.container_id)
            check("and does not start a second one for that user", second.in_use == 2)
        finally:
            await second.backend.docker.close()

        # --- capacity ----------------------------------------------------
        full = settings_for(OTPROXY_MAX_SANDBOXES="2", OTPROXY_EVICT_MIN_IDLE="3600")
        crowded = SandboxManager(full, DockerSandboxBackend(full, client))
        await crowded.start()
        try:
            refused = False
            try:
                await crowded.acquire(Scope("carol"))
            except CapacityError:
                refused = True
            check("a full host refuses instead of overcommitting", refused)
        finally:
            for task in crowded._tasks:
                task.cancel()

        # --- the warm pool ------------------------------------------------
        warm_settings = settings_for(OTPROXY_POOL_SIZE="1", OTPROXY_REAP_INTERVAL="1")
        warm_manager = SandboxManager(warm_settings, DockerSandboxBackend(warm_settings, client))
        await warm_manager.start()
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not warm_manager._warm:
                await asyncio.sleep(0.2)
            check("a warm container is started up front", len(warm_manager._warm) == 1)
            if warm_manager._warm:
                warm = warm_manager._warm[0]
                info = await client.inspect_container(warm.container_id)
                check("an unclaimed container has no network but 'none'",
                      list(info["NetworkSettings"]["Networks"]) == ["none"],
                      str(list(info["NetworkSettings"]["Networks"])))
                claimed = await warm_manager.acquire(Scope("frank"))
                check("the warm container is handed over, not replaced",
                      claimed.container_id == warm.container_id)
                check("and renamed after the user's scope", claimed.name.endswith(claimed.key))
                info = await client.inspect_container(claimed.container_id)
                check("it now sits on the user's network only",
                      list(info["NetworkSettings"]["Networks"]) == [claimed.network],
                      str(list(info["NetworkSettings"]["Networks"])))
                network = await client.inspect_network(claimed.network)
                check("that network is internal too", network["Internal"] is True)
                output = await probe_from(warm_manager, claimed.container_id, ("1.1.1.1", 443))
                check("a claimed warm container cannot reach the internet either",
                      "REACHABLE" not in output, output.strip())
                response = await probe.get(f"{claimed.base_url}/health")
                check("and it answers through its new address", response.status_code == 200)
        finally:
            for task in warm_manager._tasks:
                task.cancel()
            await asyncio.sleep(0)
            for sandbox in list(warm_manager._sandboxes.values()) + list(warm_manager._warm):
                await warm_manager.backend.destroy(sandbox)

        # --- reaping ------------------------------------------------------
        alice.last_used = time.time() - 10_000
        bob.last_used = time.time() - 10_000
        await manager._reap_once()
        check("idle sandboxes are removed", await client.inspect_container(alice.container_id) is None)
        check("their networks go with them", await client.inspect_network(alice.network) is None)
        check("the manager is empty again", manager.in_use == 0)

        # --- a shared network really is weaker (hence the default) -------
        shared = settings_for(OTPROXY_NETWORK_MODE="shared", OTPROXY_SHARED_NETWORK=f"{PREFIX}-shared")
        shared_manager = SandboxManager(shared, DockerSandboxBackend(shared, client))
        await shared_manager.start()
        try:
            one = await shared_manager.acquire(Scope("dora"))
            two = await shared_manager.acquire(Scope("erin"))
            output = await probe_from(shared_manager, one.container_id, (two.ip, shared.upstream_port))
            check("on a shared network sandboxes can see each other -- documented, not recommended",
                  "REACHABLE" in output, output.strip())
            output = await probe_from(shared_manager, one.container_id, ("1.1.1.1", 443))
            check("a shared network is still cut off from the internet", "REACHABLE" not in output,
                  output.strip())
        finally:
            for task in shared_manager._tasks:
                task.cancel()
            await shared_manager._reap_once()
    finally:
        await probe.aclose()
        for task in manager._tasks:
            task.cancel()
        await cleanup(client)
        await client.close()

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
