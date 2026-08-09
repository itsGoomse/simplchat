"""Message protocol: defines the wire format and replay protection.

This module is the "API contract" between senders and receivers. It defines:
  - The structure of a message payload (the JSON schema).
  - A ReplayGuard that prevents an attacker from re-sending a captured message.

The crypto layer (crypto.py) produces and consumes the raw payload dicts.
This module adds the protocol-level fields (version, sender, recipients,
timestamp) and the replay protection on top.
"""

import json
import os
import time
from dataclasses import dataclass, field

# Current protocol version. Bump this if the wire format changes so that
# old clients can detect incompatible messages.
PROTOCOL_VERSION = 1

# Maximum age (in seconds) a message is considered fresh. Messages older than
# this are rejected as replays. 300s = 5 minutes.
MAX_MESSAGE_AGE_SECONDS = 300


@dataclass
class Message:
    """A fully-formed, protocol-level message ready to be sent.

    Attributes:
        version: Protocol version (for forward compatibility).
        sender: Username of the sender.
        recipients: List of recipient usernames.
        timestamp: Unix time (seconds) when the message was created.
        payload: The crypto payload dict from crypto.encrypt_for_recipients.
    """

    version: int = PROTOCOL_VERSION
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    timestamp: int = 0
    payload: dict = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize this message to a JSON string for transport/storage."""
        return json.dumps({
            "version": self.version,
            "sender": self.sender,
            "recipients": self.recipients,
            "timestamp": self.timestamp,
            "payload": self.payload,
        })

    @classmethod
    def from_json(cls, data: str) -> "Message":
        """Parse a JSON string back into a Message object."""
        obj = json.loads(data)
        return cls(
            version=obj.get("version", PROTOCOL_VERSION),
            sender=obj.get("sender", ""),
            recipients=obj.get("recipients", []),
            timestamp=obj.get("timestamp", 0),
            payload=obj.get("payload", {}),
        )


class ReplayGuard:
    """Tracks seen message timestamps to detect and reject replays.

    A replay attack is when an attacker captures a valid message and re-sends
    it later. Because the signature still verifies, the recipient would accept
    it again. ReplayGuard rejects messages that are:
      - Too old (beyond MAX_MESSAGE_AGE_SECONDS), or
      - Already seen (same sender + timestamp combination).

    The seen set is persisted to disk so it survives restarts. This prevents
    an attacker from replaying a message after the client restarts.

    Pass persist=False for short-lived processes (like the local web UI
    server) that should not write a replay file to disk.
    """

    def __init__(self, path: str = "replay_guard.json", persist: bool = True) -> None:
        self.path = path
        self.persist = persist
        # Set of (sender, timestamp) tuples we have already accepted.
        self._seen: set[tuple[str, int]] = set()
        if self.persist:
            self._load()

    def _load(self) -> None:
        """Load the seen set from disk if the file exists."""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # The file stores a list of [sender, timestamp] pairs.
            self._seen = {(sender, ts) for sender, ts in data}

    def _save(self) -> None:
        """Persist the seen set to disk (no-op if persist is disabled)."""
        if not self.persist:
            return
        # Convert the set of tuples to a JSON-serializable list of lists.
        data = [[sender, ts] for sender, ts in self._seen]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def is_fresh(self, message: Message) -> bool:
        """Return True if the message is fresh (not a replay), else False.

        A message is rejected if:
          - Its timestamp is in the future (clock skew / tampering), or
          - It is older than MAX_MESSAGE_AGE_SECONDS, or
          - The (sender, timestamp) pair was already seen.
        """
        now = int(time.time())

        # Reject messages from the future (allows a small clock-skew margin).
        if message.timestamp > now + MAX_MESSAGE_AGE_SECONDS:
            return False

        # Reject messages that are too old.
        if now - message.timestamp > MAX_MESSAGE_AGE_SECONDS:
            return False

        # Reject messages we have already seen (same sender + timestamp).
        key = (message.sender, message.timestamp)
        if key in self._seen:
            return False

        # Otherwise it is fresh: record it, persist it, and accept.
        self._seen.add(key)
        self._save()
        return True
