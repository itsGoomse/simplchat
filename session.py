"""Session / remember-me cache for simplchat.

When a user logs in with a password, their private keys are encrypted with a
key derived from that password. If "remember me" is enabled, we cache the
derived key in the OS keyring so the user doesn't have to re-enter their
password on subsequent launches.

The cached key is stored in the OS keyring (not a plain file), so it is
protected by the operating system's credential store.
"""

import keyring

SERVICE = "simplchat"


def cache_unlock_key(username: str, derived_key: bytes) -> None:
    """Cache the password-derived key for a user (remember me).

    Args:
        username: The username.
        derived_key: The 32-byte key derived from the password.
    """
    keyring.set_password(SERVICE, f"{username}_unlock", derived_key.hex())


def get_cached_unlock_key(username: str) -> bytes | None:
    """Return the cached unlock key for a user, or None if not cached.

    Args:
        username: The username.

    Returns:
        The cached 32-byte key, or None if remember-me wasn't enabled.
    """
    cached = keyring.get_password(SERVICE, f"{username}_unlock")
    if cached is None:
        return None
    return bytes.fromhex(cached)


def clear_unlock_key(username: str) -> None:
    """Remove the cached unlock key for a user (logout / forget me)."""
    keyring.delete_password(SERVICE, f"{username}_unlock")
