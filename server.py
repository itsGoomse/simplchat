"""WebSocket relay server for simplchat.

This is the central server that connects clients. It handles:
  - Registration: clients send their username + public keys, which the server
    stores in the KeyDirectory (TOFU).
  - Presence: the server tracks which users are currently online.
  - Relaying: when a message arrives, the server forwards it to the recipient
    if they are online, or stores it in SQLite for later delivery if offline.

The server does NOT see message contents — the crypto layer encrypts and signs
messages end-to-end. The server only moves opaque JSON payloads around.

Run with:  uv run python server.py
"""

import asyncio
import json
import os
import ssl
import sqlite3

import websockets

from config import load_config
from key_directory import KeyDirectory


class ChatServer:
    """A minimal WebSocket relay server.

    Attributes:
        config: Server settings loaded from config.toml.
        key_dir: The public key directory (TOFU identity store).
        clients: Mapping of {username: websocket} for currently online users.
        db: SQLite connection for storing undelivered messages.
        ssl_context: TLS context if TLS is enabled, else None.
    """

    def __init__(self) -> None:
        # Load all settings from the TOML config file.
        self.config = load_config()
        self.key_dir = KeyDirectory()
        # Build the TLS context if TLS is enabled in the config.
        self.ssl_context = self._make_ssl_context()
        # username -> websocket for online users. This doubles as the
        # presence list: if a username is here, they are online.
        self.clients: dict[str, websockets.WebSocketServerProtocol] = {}
        # SQLite store for messages to offline recipients.
        self.db = sqlite3.connect("messages.db")
        self._init_db()

    def _make_ssl_context(self) -> ssl.SSLContext | None:
        """Create a TLS context from the configured certificate files.

        Returns:
            An SSLContext if TLS is enabled and the cert/key files exist,
            else None (which means the server runs without TLS).
        """
        if not self.config.tls_enabled:
            return None
        if not (os.path.exists(self.config.cert_file) and os.path.exists(self.config.key_file)):
            return None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.config.cert_file, self.config.key_file)
        return context

    def _init_db(self) -> None:
        """Create the messages and history tables if they do not exist."""
        # 'messages' holds undelivered messages for offline recipients.
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                message_json TEXT NOT NULL
            )
            """
        )
        # 'history' holds the encrypted message history. Messages are stored
        # as ciphertext, so the server never sees plaintext. This lets a
        # client fetch its full history on a new device.
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                message_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        self.db.commit()

    def _store_offline(self, recipient: str, message_json: str) -> None:
        """Persist a message for a recipient who is currently offline."""
        self.db.execute(
            "INSERT INTO messages (recipient, message_json) VALUES (?, ?)",
            (recipient, message_json),
        )
        self.db.commit()

    def _deliver_offline(self, recipient: str) -> list[str]:
        """Fetch and delete all queued messages for a recipient.

        Returns:
            A list of message JSON strings that were waiting.
        """
        rows = self.db.execute(
            "SELECT id, message_json FROM messages WHERE recipient = ?",
            (recipient,),
        ).fetchall()
        # Delete the fetched messages so they are not delivered twice.
        self.db.execute("DELETE FROM messages WHERE recipient = ?", (recipient,))
        self.db.commit()
        return [row[1] for row in rows]

    def _store_history(self, recipient: str, message_json: str) -> None:
        """Append an encrypted message to a recipient's history.

        The message is stored as ciphertext (already encrypted by the sender),
        so the server stores it without ever seeing the plaintext.
        """
        import time

        self.db.execute(
            "INSERT INTO history (recipient, message_json, created_at) VALUES (?, ?, ?)",
            (recipient, message_json, int(time.time())),
        )
        self.db.commit()

    def _get_history(self, recipient: str) -> list[str]:
        """Return all stored encrypted messages for a recipient, oldest first.

        Returns:
            A list of message JSON strings (still encrypted).
        """
        rows = self.db.execute(
            "SELECT message_json FROM history WHERE recipient = ? ORDER BY id",
            (recipient,),
        ).fetchall()
        return [row[0] for row in rows]

    async def _handle_register(self, websocket, data: dict) -> None:
        """Register a client: store their keys and mark them online.

        Args:
            websocket: The client's connection.
            data: The registration payload with username and public keys.
        """
        username = data["username"]
        enc_pub = data["enc_pub"]
        sig_pub = data["sig_pub"]

        # Store the public keys using TOFU. If the key changed for an existing
        # user, we still accept the connection but could warn here.
        self.key_dir.add_key(username, enc_pub)
        self.key_dir.add_key(f"{username}_sig", sig_pub)

        # Mark the user online and remember their connection.
        self.clients[username] = websocket

        # Confirm registration FIRST so the client knows it is connected.
        await websocket.send(json.dumps({"type": "registered", "username": username}))

        # Then deliver any messages that arrived while they were offline.
        for message_json in self._deliver_offline(username):
            await websocket.send(message_json)

    async def _handle_message(self, websocket, data: dict) -> None:
        """Relay a message to its recipients.

        Args:
            websocket: The sender's connection (unused, kept for symmetry).
            data: The message payload with sender, recipients, and message JSON.
        """
        sender = data["sender"]
        recipients = data["recipients"]
        message_json = data["message"]

        # Forward the message to each recipient.
        for recipient in recipients:
            # Skip the sender themselves (they already have their copy).
            if recipient == sender:
                continue
            # Always append to the recipient's encrypted history.
            self._store_history(recipient, message_json)
            # If the recipient is online, send immediately.
            if recipient in self.clients:
                await self.clients[recipient].send(message_json)
            else:
                # Otherwise store it for later delivery.
                self._store_offline(recipient, message_json)

    async def _handle_history(self, websocket, data: dict) -> None:
        """Send a client its full encrypted message history.

        Args:
            websocket: The client's connection.
            data: The request payload with the username.
        """
        username = data["username"]
        history = self._get_history(username)
        # Send the history as a list of encrypted message JSON strings.
        await websocket.send(json.dumps({
            "type": "history",
            "messages": history,
        }))

    async def handler(self, websocket) -> None:
        """Handle a single client connection.

        Reads incoming messages in a loop and dispatches them by type.
        """
        try:
            async for raw in websocket:
                data = json.loads(raw)
                msg_type = data.get("type")

                if msg_type == "register":
                    await self._handle_register(websocket, data)
                elif msg_type == "message":
                    await self._handle_message(websocket, data)
                elif msg_type == "history":
                    await self._handle_history(websocket, data)
                else:
                    await websocket.send(json.dumps({"type": "error", "error": "unknown type"}))
        finally:
            # When the connection closes, remove the user from the presence list.
            for username, ws in list(self.clients.items()):
                if ws is websocket:
                    del self.clients[username]
                    break

    async def run(self) -> None:
        """Start the WebSocket server and serve forever."""
        # Pass the SSL context to enable TLS if configured.
        async with websockets.serve(
            self.handler, self.config.host, self.config.port, ssl=self.ssl_context
        ):
            scheme = "wss" if self.ssl_context else "ws"
            # Report the public domain so clients know the correct address.
            print(f"Server listening on {scheme}://{self.config.host}:{self.config.port}")
            print(f"Public address: {scheme}://{self.config.domain}:{self.config.port}")
            await asyncio.Future()  # run forever


def main() -> None:
    """Entry point for the relay server (used by the 'simplchat-server' command)."""
    server = ChatServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
