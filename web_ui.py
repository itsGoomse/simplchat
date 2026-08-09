"""Local web UI server for simplchat.

This runs a small HTTP + WebSocket server on the CLIENT's device (on an
unused port). It serves a chat page in the browser and acts as a bridge:

    Browser <--WebSocket--> Local server <--WebSocket--> Remote chat server

The local server does all the crypto in Python (reusing crypto.py), so the
browser never handles keys or ciphertext. The browser just sends/receives
plaintext over the local connection.

Run with:  uv run python web_ui.py <username>
Then open http://localhost:8080 in a browser.
"""

import asyncio
import json
import os
import sys

from aiohttp import web, WSMsgType

import crypto
import websockets
from websockets.asyncio.client import ClientConnection
from groups import GroupManager
from key_directory import KeyDirectory
from protocol import Message, ReplayGuard
from servers import ServerRegistry

# Local web server settings.
LOCAL_HOST = "127.0.0.1"
# Port 0 tells the OS to pick a free port automatically.
LOCAL_PORT = 0

# Directory containing the static web files (index.html, style.css).
# Resolved relative to this file so it works whether the app is run from the
# project directory or via the installed 'simplchat-web' launcher.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(BASE_DIR, "index.html")
CSS_PATH = os.path.join(BASE_DIR, "style.css")

# Remote chat server address (matches server.py).
REMOTE_SERVER_URL = "ws://localhost:8765"


class WebUI:
    """Bridges a browser to the remote chat server, doing crypto locally.

    Attributes:
        username: The logged-in user.
        key_dir: Local public key directory (TOFU).
        groups: Local group manager.
        replay_guard: Rejects replayed messages (in-memory, short-lived).
        remote_ws: Connection to the remote chat server.
        browser_ws: Connection to the browser.
    """

    def __init__(self, username: str, server_url: str = REMOTE_SERVER_URL) -> None:
        self.username = username
        self.server_url = server_url
        self.key_dir = KeyDirectory()
        self.groups = GroupManager()
        # In-memory replay guard: this process is short-lived, so we don't
        # persist the seen set to disk.
        self.replay_guard = ReplayGuard(persist=False)
        # Typed as Optional so the type checker knows these may be None until
        # connect_remote() and handle_browser() set them.
        self.remote_ws: ClientConnection | None = None
        self.browser_ws: web.WebSocketResponse | None = None
        # Queue for history responses. remote_loop is the single reader of the
        # remote websocket, so history responses are routed through this queue
        # to avoid two coroutines calling recv() at once.
        self.history_queue: asyncio.Queue = asyncio.Queue()

    # --- Remote server connection ---

    async def connect_remote(self) -> None:
        """Connect to the remote chat server and register as this user."""
        self.remote_ws = await websockets.connect(self.server_url)

        # Load this user's public keys.
        enc_priv = crypto.load_private_key(self.username)
        sig_priv = crypto.load_signing_key(self.username)
        enc_pub = crypto.public_key_from_private(enc_priv)
        sig_pub = crypto.public_key_from_private(sig_priv)

        # Register with the remote server.
        await self.remote_ws.send(json.dumps({
            "type": "register",
            "username": self.username,
            "enc_pub": enc_pub,
            "sig_pub": sig_pub,
        }))
        response = json.loads(await self.remote_ws.recv())
        if response.get("type") != "registered":
            raise RuntimeError(f"Registration failed: {response}")

    async def remote_loop(self) -> None:
        """Receive messages from the remote server and forward to the browser.

        This is the SINGLE reader of the remote websocket. It handles two
        kinds of frames:
          - A serialized Message (relayed chat message): decrypt and forward.
          - A history response ({"type": "history", ...}): route to the queue
            so _send_history can pick it up.
        """
        # remote_ws is set by connect_remote() before this loop starts.
        assert self.remote_ws is not None
        async for raw in self.remote_ws:
            # The frame may be str or bytes; normalize to str.
            text = raw.decode() if isinstance(raw, bytes) else raw

            # Try to parse as a history response first.
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue

            if data.get("type") == "history":
                # Route the history response to the waiting coroutine.
                await self.history_queue.put(data)
                continue

            # Otherwise it is a serialized Message.
            message = Message.from_json(text)

            # Reject replays.
            if not self.replay_guard.is_fresh(message):
                continue

            # Load the sender's public key and this user's private key.
            sender_sig_pub = self.key_dir.get_key(f"{message.sender}_sig")
            enc_priv = crypto.load_private_key(self.username)
            if sender_sig_pub is None:
                continue

            # Decrypt and verify.
            try:
                plaintext = crypto.decrypt_message(
                    message.payload, self.username, enc_priv, sender_sig_pub
                )
            except (ValueError, KeyError):
                continue

            # Forward the plaintext to the browser.
            if self.browser_ws is not None:
                await self.browser_ws.send_str(json.dumps({
                    "type": "message",
                    "sender": message.sender,
                    "text": plaintext.decode(),
                }))

    # --- Browser handling ---

    async def handle_browser(self, request: web.Request) -> web.WebSocketResponse:
        """Handle a browser WebSocket connection."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.browser_ws = ws

        # Start the remote receive loop in the background.
        remote_task = asyncio.create_task(self.remote_loop())

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    await self._handle_browser_message(data)
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            remote_task.cancel()
            self.browser_ws = None
        return ws

    async def _handle_browser_message(self, data: dict) -> None:
        """Handle a command from the browser."""
        action = data.get("action")

        if action == "send":
            await self._send_message(data["recipients"], data["text"])
        elif action == "history":
            await self._send_history()
        elif action == "groups":
            await self._send_groups()
        elif action == "create_group":
            self.groups.create_group(data["name"], data["members"])
            await self._send_groups()
        elif action == "users":
            await self._send_users()

    async def _send_message(self, recipients: list[str], text: str) -> None:
        """Encrypt and send a message to the given recipients."""
        # Both connections are established before the browser can send.
        assert self.remote_ws is not None and self.browser_ws is not None

        # Build the {username: public_pem} mapping.
        recipient_keys = {}
        for username in recipients:
            enc_pub = self.key_dir.get_key(username)
            if enc_pub is None:
                await self.browser_ws.send_str(json.dumps({
                    "type": "error", "error": f"No public key for '{username}'"
                }))
                return
            recipient_keys[username] = enc_pub

        # Load this user's signing key.
        sig_priv = crypto.load_signing_key(self.username)
        sig_pub = crypto.public_key_from_private(sig_priv)

        # Build the encrypted, signed message.
        message = crypto.build_message(
            self.username, recipient_keys, text, sig_priv, sig_pub
        )

        # Send to the remote server for relaying.
        await self.remote_ws.send(json.dumps({
            "type": "message",
            "sender": self.username,
            "recipients": recipients,
            "message": message.to_json(),
        }))

        # Echo the sent message back to the browser so the sender sees it too.
        # The server skips the sender when relaying, so without this the
        # sender would never see their own message.
        if self.browser_ws is not None:
            await self.browser_ws.send_str(json.dumps({
                "type": "message",
                "sender": self.username,
                "text": text,
            }))

    async def _send_history(self) -> None:
        """Fetch encrypted history from the remote server and forward it."""
        # Both connections are established before the browser can send.
        assert self.remote_ws is not None and self.browser_ws is not None

        # Request history from the remote server. The response is routed to
        # history_queue by remote_loop (the single reader), so we wait on the
        # queue rather than calling recv() ourselves.
        await self.remote_ws.send(json.dumps({
            "type": "history",
            "username": self.username,
        }))
        response = await self.history_queue.get()
        messages = response.get("messages", [])

        # Decrypt each stored message and forward as plaintext.
        decrypted = []
        enc_priv = crypto.load_private_key(self.username)
        for message_json in messages:
            message = Message.from_json(message_json)
            sender_sig_pub = self.key_dir.get_key(f"{message.sender}_sig")
            if sender_sig_pub is None:
                continue
            try:
                plaintext = crypto.decrypt_message(
                    message.payload, self.username, enc_priv, sender_sig_pub
                )
                decrypted.append({
                    "sender": message.sender,
                    "text": plaintext.decode(),
                    "timestamp": message.timestamp,
                })
            except (ValueError, KeyError):
                continue

        await self.browser_ws.send_str(json.dumps({
            "type": "history", "messages": decrypted
        }))

    async def _send_groups(self) -> None:
        """Send the list of groups and their members to the browser."""
        assert self.browser_ws is not None
        groups = {
            name: self.groups.get_members(name)
            for name in self.groups.list_groups()
        }
        await self.browser_ws.send_str(json.dumps({
            "type": "groups", "groups": groups
        }))

    async def _send_users(self) -> None:
        """Send the list of known users to the browser.

        The key directory stores both encryption keys (username) and signing
        keys (username_sig). Only the plain usernames are real people you can
        message, so the '_sig' entries are filtered out.
        """
        assert self.browser_ws is not None
        users = [
            u for u in self.key_dir.all_users()
            if not u.endswith("_sig")
        ]
        await self.browser_ws.send_str(json.dumps({
            "type": "users", "users": users
        }))

    # --- HTTP handlers ---

    async def index(self, request: web.Request) -> web.Response:
        """Serve the chat HTML page from the static index.html file."""
        with open(HTML_PATH, "r", encoding="utf-8") as f:
            return web.Response(text=f.read(), content_type="text/html")

    async def style(self, request: web.Request) -> web.Response:
        """Serve the stylesheet from the static style.css file."""
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            return web.Response(text=f.read(), content_type="text/css")

    async def run(self) -> None:
        """Start the local web server."""
        await self.connect_remote()

        app = web.Application()
        app.router.add_get("/", self.index)
        app.router.add_get("/style.css", self.style)
        app.router.add_get("/ws", self.handle_browser)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, LOCAL_HOST, LOCAL_PORT)
        await site.start()
        # Report the actual port the OS assigned (since we used port 0).
        # site._server is the asyncio server; its sockets hold the bound port.
        actual_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        print(f"Web UI running at http://{LOCAL_HOST}:{actual_port}")
        print(f"Connected to remote server '{self.server_url}' as '{self.username}'")
        print("Press Ctrl+C to stop.")
        await asyncio.Future()  # run forever


def choose_server() -> str:
    """Let the user pick a server from the registry, or use the default.

    Returns:
        The WebSocket URL of the chosen server.
    """
    registry = ServerRegistry()
    servers = registry.list_servers()

    if not servers:
        print(f"No servers configured. Using default: {REMOTE_SERVER_URL}")
        return REMOTE_SERVER_URL

    print("Available servers:")
    for i, s in enumerate(servers, 1):
        print(f"  {i}. {s['name']} ({s['url']})")

    choice = input(f"Choose a server [1-{len(servers)}] or Enter for default: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(servers):
        return servers[int(choice) - 1]["url"]
    return REMOTE_SERVER_URL


def main() -> None:
    """Entry point for the web UI (used by the 'simplchat-web' command).

    Usage: simplchat-web <username>
    """
    if len(sys.argv) != 2:
        print("Usage: simplchat-web <username>")
        sys.exit(1)
    server_url = choose_server()
    ui = WebUI(sys.argv[1], server_url)
    asyncio.run(ui.run())


if __name__ == "__main__":
    main()
