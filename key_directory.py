"""Public key directory with Trust-On-First-Use (TOFU) verification.

This module solves the identity problem: how do you know a public key really
belongs to the person you think it does?

Approach (TOFU, like SSH):
  - The first time you see a user's public key, you trust and store it.
  - On later messages, if the key CHANGES, you warn the user — this could be
    a man-in-the-middle attack.

Public keys are NOT secret, so they are stored in a plain JSON file on disk
(rather than the OS keyring, which is for private keys).
"""

import json
import os
from typing import Optional

# Default location for the public key directory file.
DEFAULT_DIRECTORY_PATH = "key_directory.json"


class KeyDirectory:
    """A persistent store of {username: public_pem} with TOFU checks.

    Attributes:
        path: Filesystem path to the JSON file backing this directory.
    """

    def __init__(self, path: str = DEFAULT_DIRECTORY_PATH) -> None:
        self.path = path
        self._keys: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        """Load the directory from disk if the file exists."""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self._keys = json.load(f)

    def _save(self) -> None:
        """Persist the directory to disk."""
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._keys, f, indent=2)

    def add_key(self, username: str, public_pem: str) -> bool:
        """Register a public key for a user using TOFU.

        Returns:
            True if the key was accepted (new user, or key unchanged).
            False if the key CHANGED for an existing user (possible MITM).
        """
        if username not in self._keys:
            # First time seeing this user: trust and store.
            self._keys[username] = public_pem
            self._save()
            return True

        if self._keys[username] == public_pem:
            # Same key as before: all good.
            return True

        # Key changed for an existing user: this is suspicious.
        return False

    def get_key(self, username: str) -> Optional[str]:
        """Return the stored public key for a user, or None if unknown."""
        return self._keys.get(username)

    def has_key(self, username: str) -> bool:
        """Return True if we have a stored key for the user."""
        return username in self._keys

    def all_users(self) -> list[str]:
        """Return the list of usernames we have keys for."""
        return list(self._keys.keys())
