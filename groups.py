"""Group management for simplchat.

A group is a named list of usernames. When you send to a group, the client
expands the group name into its member list and encrypts for each member
(which crypto.encrypt_for_recipients already supports).

Groups are stored in a plain JSON file (like the key directory) because they
contain no secrets — just usernames.
"""

import json
import os

# Default location for the groups file.
DEFAULT_GROUPS_PATH = "groups.json"


class GroupManager:
    """A persistent store of {group_name: [usernames]}.

    Attributes:
        path: Filesystem path to the JSON file backing this store.
    """

    def __init__(self, path: str = DEFAULT_GROUPS_PATH) -> None:
        self.path = path
        self._groups: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        """Load groups from disk if the file exists."""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self._groups = json.load(f)

    def _save(self) -> None:
        """Persist groups to disk."""
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._groups, f, indent=2)

    def create_group(self, name: str, members: list[str]) -> bool:
        """Create a new group with the given members.

        Args:
            name: The group name.
            members: List of member usernames.

        Returns:
            True if created, False if the group already exists.
        """
        if name in self._groups:
            return False
        self._groups[name] = list(members)
        self._save()
        return True

    def add_member(self, name: str, username: str) -> bool:
        """Add a member to an existing group.

        Returns:
            True if added, False if the group doesn't exist or the member
            is already in it.
        """
        if name not in self._groups:
            return False
        if username in self._groups[name]:
            return False
        self._groups[name].append(username)
        self._save()
        return True

    def remove_member(self, name: str, username: str) -> bool:
        """Remove a member from a group.

        Returns:
            True if removed, False if the group doesn't exist or the member
            isn't in it.
        """
        if name not in self._groups:
            return False
        if username not in self._groups[name]:
            return False
        self._groups[name].remove(username)
        self._save()
        return True

    def get_members(self, name: str) -> list[str]:
        """Return the member list for a group, or [] if it doesn't exist."""
        return list(self._groups.get(name, []))

    def list_groups(self) -> list[str]:
        """Return the names of all groups."""
        return list(self._groups.keys())

    def has_group(self, name: str) -> bool:
        """Return True if the group exists."""
        return name in self._groups
