"""Server registry for simplchat clients.

This stores a list of known chat servers so a client can choose which one to
connect to, instead of hardcoding a single address. The list is kept in a
plain JSON file (servers.json) because it contains no secrets.

Each server entry is: {"name": <display name>, "url": <ws:// or wss:// URL>}
"""

import json
import os

# Default location for the server list file.
DEFAULT_SERVERS_PATH = "servers.json"


class ServerRegistry:
    """A persistent list of known chat servers.

    Attributes:
        path: Filesystem path to the JSON file backing this registry.
    """

    def __init__(self, path: str = DEFAULT_SERVERS_PATH) -> None:
        self.path = path
        self._servers: list[dict[str, str]] = []
        self._load()

    def _load(self) -> None:
        """Load the server list from disk if the file exists."""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self._servers = json.load(f)

    def _save(self) -> None:
        """Persist the server list to disk."""
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._servers, f, indent=2)

    def add_server(self, name: str, url: str) -> bool:
        """Add a server to the list.

        Args:
            name: A display name for the server.
            url: The WebSocket URL (ws:// or wss://).

        Returns:
            True if added, False if a server with the same URL already exists.
        """
        if any(s["url"] == url for s in self._servers):
            return False
        self._servers.append({"name": name, "url": url})
        self._save()
        return True

    def remove_server(self, url: str) -> bool:
        """Remove a server from the list by URL.

        Returns:
            True if removed, False if it wasn't in the list.
        """
        before = len(self._servers)
        self._servers = [s for s in self._servers if s["url"] != url]
        if len(self._servers) != before:
            self._save()
            return True
        return False

    def list_servers(self) -> list[dict[str, str]]:
        """Return the list of known servers."""
        return list(self._servers)

    def get_url(self, name: str) -> str | None:
        """Return the URL for a server by name, or None if unknown."""
        for s in self._servers:
            if s["name"] == name:
                return s["url"]
        return None

    def has_servers(self) -> bool:
        """Return True if at least one server is registered."""
        return len(self._servers) > 0
