"""Turning request headers into a sandbox identity, safely.

Three things come from outside and end up in a container name, a network name or
a Docker label: the user id Open WebUI sends, the terminal-context id it sends
for orchestrator connections, and the policy id from the URL.  None of them is
pasted into a name as-is -- the name is derived from a hash, and the raw values
are only ever stored in labels after validation.  That keeps a hostile value
from colliding with another user's sandbox or from producing an invalid name.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import List, Optional

#: Anything outside this is rejected rather than cleaned up: a user id Open WebUI
#: sends is a UUID, and a surprise here means something else is calling us.
_SAFE_ID = re.compile(r"[A-Za-z0-9._:@+-]{1,128}")


class InvalidIdentity(ValueError):
    """The caller's identity headers cannot be used."""


def check_id(value: str, *, what: str) -> str:
    value = (value or "").strip()
    if not value:
        raise InvalidIdentity(f"{what} is required")
    if not _SAFE_ID.fullmatch(value):
        raise InvalidIdentity(
            f"{what} must be 1-128 characters of letters, digits or ._:@+-"
        )
    return value


@dataclass(frozen=True)
class Scope:
    """Everything that decides *which* container a request belongs to."""

    user_id: str
    context_id: str = ""
    policy_id: str = ""

    @property
    def digest(self) -> str:
        """A stable, collision-resistant short name for this scope.

        Hashed rather than concatenated: the parts can contain separators, and a
        16-hex-character prefix of SHA-256 keeps container names short while
        leaving a 64-bit space -- far beyond the number of live sandboxes a host
        can hold.
        """
        material = "\x00".join((self.user_id, self.context_id, self.policy_id))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    @property
    def key(self) -> str:
        return self.digest

    def describe(self) -> str:
        """A log-safe description.  The user id is an opaque Open WebUI id."""
        parts: List[str] = [f"user={self.user_id}"]
        if self.context_id:
            parts.append(f"context={self.context_id}")
        if self.policy_id:
            parts.append(f"policy={self.policy_id}")
        return " ".join(parts)


def names(prefix: str, digest: str) -> "Names":
    return Names(
        container=f"{prefix}-c-{digest}",
        network=f"{prefix}-n-{digest}",
        volume=f"{prefix}-v-{digest}",
    )


@dataclass(frozen=True)
class Names:
    container: str
    network: str
    volume: str


def matches_any_key(token: Optional[str], keys: List[str]) -> bool:
    """Constant-time comparison against every accepted key.

    Every key is compared even after a match so the time taken does not depend
    on which key was sent, and a non-ASCII token is a mismatch rather than an
    exception (``compare_digest`` rejects those).
    """
    if not token:
        return False
    try:
        candidate = token.encode("utf-8")
    except UnicodeEncodeError:  # pragma: no cover -- str is always encodable
        return False
    found = False
    for key in keys:
        if hmac.compare_digest(candidate, key.encode("utf-8")):
            found = True
    return found


def bearer(authorization: Optional[str]) -> str:
    """Extract the token from an Authorization header, Bearer or bare."""
    if not authorization:
        return ""
    value = authorization.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return value
