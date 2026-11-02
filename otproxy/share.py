"""Handing a file from a sandbox to the person in the chat.

Open WebUI can only show a file from a terminal server when it is wired as an
Open Terminal connection: its ``display_file`` tool returns a path, no bytes,
and the browser then fetches that path through a route that exists only for
that connection type.  On an OpenAPI or MCP connection nothing appears, and the
model cannot tell -- it gets ``exists: true`` and reports success.

So the proxy hands the file out itself.  ``share_file`` mints a signed, short
lived URL for one file in the caller's own sandbox; the model writes that URL
into its answer, and the person's browser fetches it from the proxy with no
credential of its own.  That works on every connection type, and an image or a
PDF rendered as a Markdown link shows up in the chat.

What a link is, exactly: an HMAC over the sandbox it belongs to, the resolved
path, and an expiry.  Nothing is stored -- a link is valid because it verifies,
and invalid once it expires, once the sandbox is gone, or once the API key it
was derived from changes.  Anyone holding the URL can read that one file until
it expires, which is the price of a link that needs no login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Optional, Tuple


class BadToken(ValueError):
    """The link does not verify, or no longer applies."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception:  # noqa: BLE001 -- any malformed input is just a bad token
        raise BadToken("not a valid link") from None


@dataclass(frozen=True)
class Grant:
    """What a link is allowed to do."""

    key: str          # the sandbox's scope key
    path: str         # absolute path inside that sandbox
    expires: int      # unix seconds

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1] or "download"


def mint(secret: str, grant: Grant) -> str:
    payload = json.dumps(
        {"k": grant.key, "p": grant.path, "e": grant.expires},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()[:16]
    return f"{_b64(payload)}.{_b64(signature)}"


def verify(secret: str, token: str, *, now: Optional[float] = None) -> Grant:
    """Return the grant a token carries, or raise :class:`BadToken`."""
    parts = token.split(".")
    if len(parts) != 2:
        raise BadToken("not a valid link")
    payload, signature = _unb64(parts[0]), _unb64(parts[1])
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(signature, expected):
        raise BadToken("this link was not issued by this proxy")
    try:
        data = json.loads(payload)
        grant = Grant(key=str(data["k"]), path=str(data["p"]), expires=int(data["e"]))
    except (ValueError, KeyError, TypeError):
        raise BadToken("not a valid link") from None
    if (now or time.time()) > grant.expires:
        raise BadToken("this link has expired")
    return grant


def link(public_url: str, token: str) -> str:
    return f"{public_url}/d/{token}"


#: Added to the schema the model reads, so that handing a file over is a tool
#: like any other.  Kept deliberately explicit about what the model should do
#: with the result, because otherwise it claims the file was displayed.
def schema_fragment(ttl_minutes: int) -> Tuple[str, dict]:
    return (
        "/share",
        {
            "get": {
                "operationId": "share_file",
                "summary": "Give the user a download link for a file",
                "description": (
                    "Turn a file in your workspace into a link the user can open, valid for about "
                    f"{ttl_minutes} minutes. Use this whenever the user should receive a file: a document, "
                    "a spreadsheet, an image, an export. You cannot display files yourself -- put the "
                    "returned markdown into your answer, exactly as given, and do not claim a file was "
                    "shown or attached any other way."
                ),
                "parameters": [
                    {
                        "name": "path",
                        "in": "query",
                        "required": True,
                        "description": "Absolute path of the file in your workspace.",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "The link, and the markdown to paste into the answer.",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string"},
                                        "markdown": {"type": "string"},
                                        "name": {"type": "string"},
                                        "expires_in_seconds": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    },
                    "404": {"description": "No such file."},
                },
            }
        },
    )


def markdown_for(name: str, url: str) -> str:
    """An image shows up in the chat; everything else is a link."""
    image_suffixes = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp")
    if name.lower().endswith(image_suffixes):
        return f"![{name}]({url})"
    return f"[{name}]({url})"
