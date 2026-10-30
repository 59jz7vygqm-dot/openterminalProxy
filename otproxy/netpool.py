"""Subnet allocation for per-user sandbox networks.

Docker will pick a subnet by itself, but only out of its default address pool:
that pool holds roughly sixteen networks, and the seventeenth sandbox fails with
"all predefined address pools have been fully subnetted".  So the proxy carves
its own supernet into fixed-size blocks and asks for one explicitly.

A /29 holds eight addresses: network, broadcast, the bridge gateway, the sandbox
and the proxy -- with room to spare.  A /16 supernet then yields 8192 of them.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator


class PoolExhausted(RuntimeError):
    """No free block left in the configured supernet."""


class SubnetPool:
    def __init__(self, supernet: str, prefix: int) -> None:
        self._supernet = ipaddress.ip_network(supernet, strict=True)
        if prefix < self._supernet.prefixlen:
            raise ValueError(f"/{prefix} does not fit inside {supernet}")
        if prefix > 30:
            raise ValueError("a /31 or /32 leaves no usable host addresses")
        self._prefix = prefix

    @property
    def capacity(self) -> int:
        return 1 << (self._prefix - self._supernet.prefixlen)

    def blocks(self) -> Iterator[ipaddress.IPv4Network]:
        return self._supernet.subnets(new_prefix=self._prefix)

    def allocate(self, taken: Iterable[str]) -> str:
        """Return the first block that does not overlap anything in *taken*.

        *taken* is read from Docker on every call rather than remembered, so two
        proxy replicas on one host, or a restart, cannot hand out the same block
        twice.  Networks outside the supernet are considered too: an operator may
        have pointed the supernet at a range that is already partly in use.
        """
        used = []
        for entry in taken:
            try:
                used.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue  # an IPv6 or malformed entry cannot collide with us
        for candidate in self.blocks():
            if not any(candidate.overlaps(other) for other in used):
                return str(candidate)
        raise PoolExhausted(
            f"{self._supernet} is fully allocated at /{self._prefix} "
            f"({self.capacity} blocks); raise OTPROXY_NET_SUPERNET or lower OTPROXY_MAX_SANDBOXES"
        )

    @staticmethod
    def gateway(subnet: str) -> str:
        """The address Docker puts on the host side of the bridge."""
        return str(next(ipaddress.ip_network(subnet, strict=False).hosts()))
