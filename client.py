"""WebSocket client for simplchat.

This is the client-side counterpart to server.py. It:
  - Registers with the server (sending username + public keys).
  - Sends encrypted, signed messages to recipients.
  - Receives messages and decrypts/verifies them.

The client holds the user's private keys (from the OS keyring) and their
public key directory (TOFU). The server never sees plaintext.

Run with:  uv run python client.py <username>
"""

import asyncio
import json
import os
import ssl
import sys

import websockets

import crypto
from key_directory import KeyDirectory
from protocol import Message, ReplayGuard
from servers import ServerRegistry

# Default server address. Match the host/port in server.py.
# Use wss:// (TLS) if the server has certificates, else ws://.
SERVER_URL = "ws://localhost:8765"

# Optional CA certificate for verifying the server's TLS certificate.
# If set, the client verifies the server identity. For a self-signed cert,
# point this at the server's cert.pem file.
CA_CERT_FILE = "cert.pem"


def choose_server() -> str:
    """Let the user pick a server from the registry, or use the default.

    Returns:
        The WebSocket URL of the chosen server.
    """
    registry = ServerRegistry()
    servers = registry.list_servers()

    # If no servers are registered, fall back to the default.
    if not servers:
        print(f"No servers configured. Using default: {SERVER_URL}")
        return SERVER_URL

    # Show the list and let the user pick one.
    print("Available servers:")
    for i, s in enumerate(servers, 1):
        print(f"  {i}. {s['name']} ({s['url']})")

    choice = input(f"Choose a server [1-{len(servers)}] or Enter for default: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(servers):
        return servers[int(choice) - 1]["url"]
    return SERVER_URL


class ChatClient:
    """A single chat client connection.

    Attributes:
        username: The user's username.
        server_url: The WebSocket URL of the server to connect to.
        key_dir: Local public key directory (TOFU).
        replay_guard: Rejects replayed messages.
        ws: The active WebSocket connection.
    """

    def __init__(self, username: str, server_url: str = SERVER_URL) -> None:
        self.username = username
        self.server_url = server_url
        self.key_dir = KeyDirectory()
        self.replay_guard = ReplayGuard()
        self.ws = None

    def _make_ssl_context(self) -> ssl.SSLContext | None:
        """Create a TLS context for the client connection.

        If a CA certificate file exists, the client verifies the server's
        certificate against it. Otherwise, TLS is not used.

        Returns:
            An SSLContext if a CA cert is present, else None.
        """
        if not os.path.exists(CA_CERT_FILE):
            return None

        context = ssl.create_default_context(cafile=CA_CERT_FILE)
        return context

    async def connect(self) -> None:
        """Open the WebSocket connection and register with the server."""
        # Use TLS if a CA certificate is available.
        ssl_context = self._make_ssl_context()
        self.ws = await websockets.connect(self.server_url, ssl=ssl_context)

        # Load this user's public keys (from the keyring-stored private keys).
        enc_priv = crypto.load_private_key(self.username)
        sig_priv = crypto.load_signing_key(self.username)
        enc_pub = crypto.public_key_from_private(enc_priv)
        sig_pub = crypto.public_key_from_private(sig_priv)

        # Send the registration message to the server.
        await self.ws.send(json.dumps({
            "type": "register",
            "username": self.username,
            "enc_pub": enc_pub,
            "sig_pub": sig_pub,
        }))

        # Wait for the server to confirm registration.
        response = json.loads(await self.ws.recv())
        if response.get("type") != "registered":
            raise RuntimeError(f"Registration failed: {response}")

    async def send(self, recipients: list[str], text: str) -> None:
        """Encrypt, sign, and send a message to the given recipients.

        Args:
            recipients: List of recipient usernames.
            text: The plaintext message to send.
        """
        # Build the {username: public_pem} mapping from the key directory.
        recipient_keys = {}
        for username in recipients:
            enc_pub = self.key_dir.get_key(username)
            if enc_pub is None:
                raise KeyError(f"No public key known for '{username}'")
            recipient_keys[username] = enc_pub

        # Load this user's signing key and public key.
        sig_priv = crypto.load_signing_key(self.username)
        sig_pub = crypto.public_key_from_private(sig_priv)

        # Build a fully-formed, encrypted, signed Message.
        message = crypto.build_message(
            self.username,
            recipient_keys,
            text,
            sig_priv,
            sig_pub,
        )

        # Send the message envelope to the server for relaying.
        await self.ws.send(json.dumps({
            "type": "message",
            "sender": self.username,
            "recipients": recipients,
            "message": message.to_json(),
        }))

    async def receive_loop(self) -> None:
        """Continuously receive, decrypt, and print incoming messages.

        The server relays the raw serialized Message JSON directly (no
        envelope), so each frame is parsed as a Message.
        """
        async for raw in self.ws:
            # The server sends the serialized Message JSON directly.
            await self._handle_incoming(raw)

    async def _handle_incoming(self, message_json: str) -> None:
        """Decrypt and display a single incoming message.

        Args:
            message_json: The serialized Message JSON from the server.
        """
        message = Message.from_json(message_json)

        # Reject replayed messages.
        if not self.replay_guard.is_fresh(message):
            print(f"[{message.sender}] (replay rejected)")
            return

        # Load this user's private key and the sender's public key.
        enc_priv = crypto.load_private_key(self.username)
        sender_sig_pub = self.key_dir.get_key(f"{message.sender}_sig")
        if sender_sig_pub is None:
            print(f"[{message.sender}] (unknown sender key)")
            return

        # Decrypt and verify the message.
        try:
            plaintext = crypto.decrypt_message(
                message.payload,
                self.username,
                enc_priv,
                sender_sig_pub,
            )
            print(f"[{message.sender}] {plaintext.decode()}")
        except (ValueError, KeyError) as exc:
            print(f"[{message.sender}] (rejected: {exc})")


async def main(username: str) -> None:
    """Run the client for a given username."""
    # Let the user pick a server from the registry.
    server_url = choose_server()
    client = ChatClient(username, server_url)
    await client.connect()
    print(f"Connected as {username} to {server_url}. Type a message or 'quit' to exit.")

    # Run the receive loop in the background.
    receive_task = asyncio.create_task(client.receive_loop())

    # Simple input loop for sending messages.
    while True:
        line = await asyncio.to_thread(input, "> ")
        if line.strip().lower() == "quit":
            break
        # Format: "recipient1,recipient2: message text"
        if ":" in line:
            recipients_part, text = line.split(":", 1)
            recipients = [r.strip() for r in recipients_part.split(",") if r.strip()]
            try:
                await client.send(recipients, text.strip())
            except KeyError as exc:
                print(f"Error: {exc}")
        else:
            print("Format: recipient1,recipient2: message")

    receive_task.cancel()
    await client.ws.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: uv run python client.py <username>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
