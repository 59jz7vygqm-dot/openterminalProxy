"""otproxy -- per-user Open Terminal sandboxes behind one Open WebUI connection.

Open WebUI talks to a single terminal server URL.  This package answers at that
URL, reads the ``X-User-Id`` header Open WebUI sends with every request, and
forwards the request to a container that belongs to that user alone -- starting
it on the first request and removing it again once the user goes quiet.

The containers have no route to the internet.  See README.md for the threat
model and for what this does *not* protect against.
"""

__version__ = "1.0.0"
