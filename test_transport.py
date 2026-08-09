"""End-to-end test of the WebSocket transport.

This connects two clients (alice and bob) to the running server, has alice
send a message to bob, and verifies bob receives and decrypts it.

Run with:  uv run python test_transport.py
"""

import asyncio

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
    await ws.send(json_dumps({
        "type": "register",
        "username": username,
        "enc_pub": enc_pub,
        "sig_pub": sig_pub,
    }))
    response = json_loads(await ws.recv())
    assert response["type"] == "registered", response


async def main():
    key_dir = KeyDirectory()

    # Connect both clients.
    alice_ws = await websockets.connect(SERVER_URL)
    bob_ws = await websockets.connect(SERVER_URL)
    await register_client(alice_ws, "alice")
    await register_client(bob_ws, "bob")

    # Alice builds and sends a message to bob.
    bob_enc_pub = key_dir.get_key("bob")
    sig_priv = crypto.load_signing_key("alice")
    sig_pub = crypto.public_key_from_private(sig_priv)
    message = crypto.build_message(
        "alice", {"bob": bob_enc_pub}, "Hello Bob!", sig_priv, sig_pub
    )
    await alice_ws.send(json_dumps({
        "type": "message",
        "sender": "alice",
        "recipients": ["bob"],
        "message": message.to_json(),
    }))

    # Bob receives the message (server relays the raw Message JSON).
    raw = await bob_ws.recv()
    received = Message.from_json(raw)

    # Bob decrypts and verifies.
    enc_priv = crypto.load_private_key("bob")
    sender_sig_pub = key_dir.get_key("alice_sig")
    plaintext = crypto.decrypt_message(
        received.payload, "bob", enc_priv, sender_sig_pub
    )
    print(f"Bob received: {plaintext.decode()}")
    assert plaintext == b"Hello Bob!"

    # --- Test offline delivery ---
    # Alice sends a message to carol, who is NOT connected.
    carol_ws = await websockets.connect(SERVER_URL)
    await register_client(carol_ws, "carol")
    await carol_ws.close()  # carol goes offline

    carol_enc_pub = key_dir.get_key("carol")
    message2 = crypto.build_message(
        "alice", {"carol": carol_enc_pub}, "Offline hello", sig_priv, sig_pub
    )
    await alice_ws.send(json_dumps({
        "type": "message",
        "sender": "alice",
        "recipients": ["carol"],
        "message": message2.to_json(),
    }))

    # Carol reconnects and should receive the queued message.
    carol_ws = await websockets.connect(SERVER_URL)
    await register_client(carol_ws, "carol")
    raw = await carol_ws.recv()
    received2 = Message.from_json(raw)
    enc_priv = crypto.load_private_key("carol")
    carol_sig_pub = key_dir.get_key("alice_sig")
    plaintext2 = crypto.decrypt_message(
        received2.payload, "carol", enc_priv, carol_sig_pub
    )
    print(f"Carol received (offline): {plaintext2.decode()}")
    assert plaintext2 == b"Offline hello"
    await carol_ws.close()

    await alice_ws.close()
    await bob_ws.close()

    print("Transport test PASSED")


def json_dumps(obj):
    import json
    return json.dumps(obj)


def json_loads(s):
    import json
    return json.loads(s)


if __name__ == "__main__":
    asyncio.run(main())
