"""Round-trip tests for the simplchat crypto and protocol layers.

These tests verify the full flow works end-to-end:
  1. Key generation (RSA for encryption, ECDSA for signing).
  2. Encrypting a message for multiple recipients.
  3. Each recipient decrypting their own copy.
  4. Signature verification (authenticity).
  5. Replay protection.

Run with:  uv run pytest test_crypto.py
"""

import time

import pytest

import crypto
import protocol
from key_directory import KeyDirectory


def test_round_trip_single_recipient():
    """A message encrypted for one recipient decrypts back to the original."""
    # Set up Alice's keys (encryption + signing).
    alice_enc_pub, alice_enc_priv = crypto.generate_keypair()
    alice_sig_pub, alice_sig_priv = crypto.generate_signing_keypair()

    # Alice encrypts a message for Bob.
    bob_enc_pub, bob_enc_priv = crypto.generate_keypair()
    payload = crypto.encrypt_for_recipients(
        b"Hello Bob!",
        {"bob": bob_enc_pub},
        alice_sig_priv,  # signing key as PEM string
        alice_sig_pub,
    )

    # Bob decrypts it and verifies Alice's signature.
    plaintext = crypto.decrypt_message(payload, "bob", bob_enc_priv, alice_sig_pub)
    assert plaintext == b"Hello Bob!"


def test_round_trip_multiple_recipients():
    """Each recipient can decrypt their own copy of a group message."""
    alice_sig_pub, alice_sig_priv = crypto.generate_signing_keypair()

    # Two recipients, Bob and Carol.
    bob_enc_pub, bob_enc_priv = crypto.generate_keypair()
    carol_enc_pub, carol_enc_priv = crypto.generate_keypair()

    payload = crypto.encrypt_for_recipients(
        b"Group secret",
        {"bob": bob_enc_pub, "carol": carol_enc_pub},
        alice_sig_priv,
        alice_sig_pub,
    )

    # Both recipients can decrypt independently.
    assert crypto.decrypt_message(payload, "bob", bob_enc_priv, alice_sig_pub) == b"Group secret"
    assert crypto.decrypt_message(payload, "carol", carol_enc_priv, alice_sig_pub) == b"Group secret"


def test_wrong_recipient_cannot_decrypt():
    """A recipient not in the group cannot decrypt the message."""
    alice_sig_pub, alice_sig_priv = crypto.generate_signing_keypair()
    bob_enc_pub, _ = crypto.generate_keypair()

    payload = crypto.encrypt_for_recipients(
        b"Secret",
        {"bob": bob_enc_pub},
        alice_sig_priv,
        alice_sig_pub,
    )

    # Mallory is not a recipient, so there is no wrapped key for her.
    mallory_enc_pub, mallory_enc_priv = crypto.generate_keypair()
    with pytest.raises(KeyError):
        crypto.decrypt_message(payload, "mallory", mallory_enc_priv, alice_sig_pub)


def test_tampered_message_fails_verification():
    """A tampered message fails signature verification."""
    alice_sig_pub, alice_sig_priv = crypto.generate_signing_keypair()
    bob_enc_pub, bob_enc_priv = crypto.generate_keypair()

    payload = crypto.encrypt_for_recipients(
        b"Original",
        {"bob": bob_enc_pub},
        alice_sig_priv,
        alice_sig_pub,
    )

    # Tamper with the ciphertext (flip one byte).
    tampered = dict(payload)
    tampered["ciphertext"] = "A" + payload["ciphertext"][1:]

    # Tampering is detected by AES-GCM's authentication (InvalidTag), which
    # fires before signature verification. Either exception means the message
    # was rejected, which is what we want.
    from cryptography.exceptions import InvalidTag

    with pytest.raises((ValueError, InvalidTag)):
        crypto.decrypt_message(tampered, "bob", bob_enc_priv, alice_sig_pub)


def test_replay_guard_rejects_duplicate():
    """ReplayGuard rejects a message that was already seen."""
    guard = protocol.ReplayGuard()

    msg = protocol.Message(
        sender="alice",
        recipients=["bob"],
        timestamp=int(time.time()),
        payload={},
    )

    # First time: fresh.
    assert guard.is_fresh(msg) is True
    # Same message again: replay, rejected.
    assert guard.is_fresh(msg) is False


def test_replay_guard_rejects_old_message():
    """ReplayGuard rejects messages older than the allowed window."""
    guard = protocol.ReplayGuard()

    # A message timestamped far in the past.
    old_msg = protocol.Message(
        sender="alice",
        recipients=["bob"],
        timestamp=int(time.time()) - protocol.MAX_MESSAGE_AGE_SECONDS - 100,
        payload={},
    )

    assert guard.is_fresh(old_msg) is False


def test_key_directory_tofu():
    """KeyDirectory accepts new keys and flags changed keys."""
    directory = KeyDirectory(path="test_key_directory.json")

    # First time: accepted.
    assert directory.add_key("alice", "PUBLIC_KEY_A") is True
    # Same key again: accepted.
    assert directory.add_key("alice", "PUBLIC_KEY_A") is True
    # Changed key: flagged as suspicious (possible MITM).
    assert directory.add_key("alice", "PUBLIC_KEY_B") is False

    # Clean up the test file.
    import os
    if os.path.exists("test_key_directory.json"):
        os.remove("test_key_directory.json")
