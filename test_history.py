"""Test the encrypted message history feature.

This connects alice and bob, has alice send a message to bob, then verifies
bob can fetch his history from the server (still encrypted) and decrypt it.

Run with:  uv run python test_history.py
"""

import asyncio
import json

import websockets

import crypto
from key_directory import KeyDirectory
from protocol import Message

SERVER_URL = "ws://localhost:8765"


async def register_client(ws, username):
    """Register a client with the server."""
    enc_priv = crypto.load_private_key(username)
    sig_priv = crypto.load_signing_key(username)
    enc_pub = crypto.public_key_from_private(enc_priv)
    sig_pub = crypto.public_key_from_private(sig_priv)
    await ws.send(json.dumps({
        "type": "register",
        "username": username,
        "enc_pub": enc_pub,
        "sig_pub": sig_pub,
    }))
    response = json.loads(await ws.recv())
    assert response["type"] == "registered", response


async def main():
    key_dir = KeyDirectory()

    # Connect alice and bob.
    alice_ws = await websockets.connect(SERVER_URL)
    bob_ws = await websockets.connect(SERVER_URL)
    await register_client(alice_ws, "alice")
    await register_client(bob_ws, "bob")

    # Alice sends a message to bob.
    bob_enc_pub = key_dir.get_key("bob")
    sig_priv = crypto.load_signing_key("alice")
    sig_pub = crypto.public_key_from_private(sig_priv)
    message = crypto.build_message(
        "alice", {"bob": bob_enc_pub}, "History test message", sig_priv, sig_pub
    )
    await alice_ws.send(json.dumps({
        "type": "message",
        "sender": "alice",
        "recipients": ["bob"],
        "message": message.to_json(),
    }))

    # Bob receives it live.
    raw = await bob_ws.recv()
    received = Message.from_json(raw)
    enc_priv = crypto.load_private_key("bob")
    sender_sig_pub = key_dir.get_key("alice_sig")
    plaintext = crypto.decrypt_message(
        received.payload, "bob", enc_priv, sender_sig_pub
    )
    print(f"Bob received live: {plaintext.decode()}")

    # Bob requests his history from the server.
    await bob_ws.send(json.dumps({"type": "history", "username": "bob"}))
    response = json.loads(await bob_ws.recv())
    assert response["type"] == "history", response
    history = response["messages"]
    print(f"Bob has {len(history)} message(s) in history")

    # Decrypt the history.
    for message_json in history:
        hist_msg = Message.from_json(message_json)
        hist_plain = crypto.decrypt_message(
            hist_msg.payload, "bob", enc_priv, sender_sig_pub
        )
        print(f"History: {hist_msg.sender}: {hist_plain.decode()}")
        assert hist_plain == b"History test message"

    await alice_ws.close()
    await bob_ws.close()
    print("History test PASSED")


if __name__ == "__main__":
    asyncio.run(main())
