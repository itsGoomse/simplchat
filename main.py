"""Command-line entry point for simplchat.

This ties all the modules together into a usable interface. It provides
subcommands for the common operations:

  register <username>   Generate keys, encrypt them with a password, store them.
  login <username>      Unlock the user's keys with their password.
  fingerprint <username>  Show the public key fingerprint for verification.
  chat <username>       Launch the interactive chat client.
  web <username>        Launch the local web UI (opens a browser page).
  group create <name> <members>  Create a group (comma-separated members).
  group list            List all groups.
  group add <name> <user>       Add a member to a group.
  server add <name> <url>       Add a chat server to the client's list.
  server list           List known chat servers.
  server remove <url>   Remove a chat server from the list.

Run with:  uv run python main.py <command> [args]
"""

import base64
import getpass
import sys

import crypto
import keyring
import session
from groups import GroupManager
from key_directory import KeyDirectory
from servers import ServerRegistry

SERVICE = "simplchat"


def cmd_register(username: str) -> None:
    """Generate encryption + signing keys for a user and store them encrypted.

    The private keys are encrypted with a key derived from the user's
    password, so they cannot be used without the password.

    Args:
        username: The username to register.
    """
    # Prompt for a password (hidden input).
    password = getpass.getpass(f"Set a password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    # Generate the RSA encryption keypair.
    enc_pub, enc_priv = crypto.generate_keypair()
    # Generate the ECDSA signing keypair.
    sig_pub, sig_priv = crypto.generate_signing_keypair()

    # Encrypt both private keys with the password.
    enc_priv_blob, enc_priv_salt = crypto.encrypt_private_key(enc_priv, password)
    sig_priv_blob, sig_priv_salt = crypto.encrypt_private_key(sig_priv, password)

    # Store the encrypted blobs and salts in the keyring.
    keyring.set_password(SERVICE, f"{username}_private_enc", enc_priv_blob)
    keyring.set_password(SERVICE, f"{username}_private_salt", enc_priv_salt)
    keyring.set_password(SERVICE, f"{username}_signing_enc", sig_priv_blob)
    keyring.set_password(SERVICE, f"{username}_signing_salt", sig_priv_salt)

    # Publish the public keys to the local key directory (TOFU).
    key_dir = KeyDirectory()
    key_dir.add_key(username, enc_pub)
    key_dir.add_key(f"{username}_sig", sig_pub)

    print(f"Registered '{username}'.")
    print(f"Encryption key fingerprint: {crypto.public_key_fingerprint(enc_pub)}")
    print(f"Signing key fingerprint:    {crypto.public_key_fingerprint(sig_pub)}")
    print("Run 'simplchat login <username>' to unlock your keys.")


def cmd_login(username: str) -> None:
    """Unlock a user's keys with their password.

    Decrypts the stored private keys and writes them to the plaintext slots
    that the app reads. With "remember me", the derived key is cached so
    future logins don't require the password again.

    Args:
        username: The username to log in.
    """
    # Try the cached unlock key first (remember me).
    cached_key = session.get_cached_unlock_key(username)
    if cached_key is not None:
        # Re-derive the key from the cached value and decrypt.
        enc_priv_blob = keyring.get_password(SERVICE, f"{username}_private_enc")
        enc_priv_salt = keyring.get_password(SERVICE, f"{username}_private_salt")
        sig_priv_blob = keyring.get_password(SERVICE, f"{username}_signing_enc")
        sig_priv_salt = keyring.get_password(SERVICE, f"{username}_signing_salt")
        if enc_priv_blob and enc_priv_salt and sig_priv_blob and sig_priv_salt:
            # Decrypt using the cached key directly (it IS the derived key).
            enc_priv = _decrypt_with_key(enc_priv_blob, enc_priv_salt, cached_key)
            sig_priv = _decrypt_with_key(sig_priv_blob, sig_priv_salt, cached_key)
            _write_unlocked(username, enc_priv, sig_priv)
            print(f"Logged in as '{username}' (remembered).")
            return

    # Otherwise prompt for the password.
    password = getpass.getpass(f"Password for '{username}': ")

    enc_priv_blob = keyring.get_password(SERVICE, f"{username}_private_enc")
    enc_priv_salt = keyring.get_password(SERVICE, f"{username}_private_salt")
    sig_priv_blob = keyring.get_password(SERVICE, f"{username}_signing_enc")
    sig_priv_salt = keyring.get_password(SERVICE, f"{username}_signing_salt")

    if not (enc_priv_blob and enc_priv_salt and sig_priv_blob and sig_priv_salt):
        print(f"No registered keys found for '{username}'. Run 'simplchat register {username}' first.")
        sys.exit(1)

    try:
        enc_priv = crypto.decrypt_private_key(enc_priv_blob, enc_priv_salt, password)
        sig_priv = crypto.decrypt_private_key(sig_priv_blob, sig_priv_salt, password)
    except Exception:
        print("Incorrect password.")
        sys.exit(1)

    _write_unlocked(username, enc_priv, sig_priv)

    # Ask whether to remember the login.
    remember = input("Remember me on this device? [y/N]: ").strip().lower()
    if remember in ("y", "yes"):
        # Cache the derived key so future logins auto-unlock.
        derived = crypto.derive_key(password, base64.b64decode(enc_priv_salt))
        session.cache_unlock_key(username, derived)
        print("Login remembered.")

    print(f"Logged in as '{username}'.")


def _decrypt_with_key(blob_b64: str, salt_b64: str, key: bytes) -> str:
    """Decrypt a private key blob using a pre-derived key (for remember-me)."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = base64.b64decode(blob_b64)
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


def _write_unlocked(username: str, enc_priv: str, sig_priv: str) -> None:
    """Write the decrypted keys to the plaintext slots the app reads."""
    keyring.set_password(SERVICE, f"{username}_private", enc_priv)
    keyring.set_password(SERVICE, f"{username}_signing", sig_priv)


def cmd_fingerprint(username: str) -> None:
    """Print the public key fingerprint for a user.

    This is used for out-of-band verification: compare this value with the
    other party over a separate channel (phone, in person) to confirm the
    key really belongs to them.

    Args:
        username: The username whose fingerprint to show.
    """
    key_dir = KeyDirectory()
    enc_pub = key_dir.get_key(username)
    if enc_pub is None:
        print(f"No public key known for '{username}'.")
        return
    print(f"{username} encryption key fingerprint: {crypto.public_key_fingerprint(enc_pub)}")


def cmd_group_create(name: str, members: str) -> None:
    """Create a new group with comma-separated members."""
    member_list = [m.strip() for m in members.split(",") if m.strip()]
    groups = GroupManager()
    if groups.create_group(name, member_list):
        print(f"Created group '{name}' with members: {', '.join(member_list)}")
    else:
        print(f"Group '{name}' already exists.")


def cmd_group_list() -> None:
    """List all groups and their members."""
    groups = GroupManager()
    if not groups.list_groups():
        print("No groups defined.")
        return
    for name in groups.list_groups():
        print(f"{name}: {', '.join(groups.get_members(name))}")


def cmd_group_add(name: str, username: str) -> None:
    """Add a member to an existing group."""
    groups = GroupManager()
    if groups.add_member(name, username):
        print(f"Added '{username}' to group '{name}'.")
    else:
        print(f"Could not add '{username}' to '{name}' (group missing or member exists).")


def cmd_group(args: list[str]) -> None:
    """Dispatch group subcommands."""
    if len(args) >= 1 and args[0] == "create" and len(args) == 3:
        cmd_group_create(args[1], args[2])
    elif len(args) == 1 and args[0] == "list":
        cmd_group_list()
    elif len(args) == 3 and args[0] == "add":
        cmd_group_add(args[1], args[2])
    else:
        print("Usage: group create <name> <members> | group list | group add <name> <user>")


def cmd_server_add(name: str, url: str) -> None:
    """Add a chat server to the client's list."""
    registry = ServerRegistry()
    if registry.add_server(name, url):
        print(f"Added server '{name}' ({url}).")
    else:
        print(f"A server with URL '{url}' already exists.")


def cmd_server_list() -> None:
    """List all known chat servers."""
    registry = ServerRegistry()
    servers = registry.list_servers()
    if not servers:
        print("No servers configured.")
        return
    for s in servers:
        print(f"  {s['name']}: {s['url']}")


def cmd_server_remove(url: str) -> None:
    """Remove a chat server from the list by URL."""
    registry = ServerRegistry()
    if registry.remove_server(url):
        print(f"Removed server '{url}'.")
    else:
        print(f"No server with URL '{url}' found.")


def _run_daemon(username: str) -> None:
    """Launch the web UI as a detached background process.

    The child process is fully detached (new session, no controlling
    terminal), so the parent command returns immediately and the terminal
    is not blocked. Logs go to a file in the project directory.

    Args:
        username: The username to run the web UI for.
    """
    import os
    import subprocess

    # Resolve the web_ui module path so the child can run it directly.
    import web_ui
    script = os.path.join(os.path.dirname(os.path.abspath(web_ui.__file__)), "web_ui.py")

    # Open a log file for the daemon's output.
    log_path = os.path.join(os.getcwd(), "web_ui.log")
    log_file = open(log_path, "a")

    # Detach the child: new session, stdin closed, stdout/stderr to the log.
    subprocess.Popen(
        [sys.executable, script, username],
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
        close_fds=True,
    )
    print(f"Web UI started in the background for '{username}'.")
    print(f"Logs: {log_path}")
    print("To stop it: pkill -f 'web_ui.py'")


def cmd_server(args: list[str]) -> None:
    """Dispatch server subcommands."""
    if len(args) >= 1 and args[0] == "add" and len(args) == 3:
        cmd_server_add(args[1], args[2])
    elif len(args) == 1 and args[0] == "list":
        cmd_server_list()
    elif len(args) == 2 and args[0] == "remove":
        cmd_server_remove(args[1])
    else:
        print("Usage: server add <name> <url> | server list | server remove <url>")


def main() -> None:
    """Parse the command line and dispatch to the appropriate subcommand."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "register" and len(sys.argv) == 3:
        cmd_register(sys.argv[2])
    elif command == "login" and len(sys.argv) == 3:
        cmd_login(sys.argv[2])
    elif command == "fingerprint" and len(sys.argv) == 3:
        cmd_fingerprint(sys.argv[2])
    elif command == "chat" and len(sys.argv) == 3:
        # Launch the interactive chat client (imported lazily to avoid
        # requiring websockets for the other subcommands).
        import asyncio
        from client import main as chat_main
        asyncio.run(chat_main(sys.argv[2]))
    elif command == "web" and len(sys.argv) in (3, 4):
        # Launch the local web UI (imported lazily). This uses the same
        # server-selection flow as running web_ui.py directly.
        # Optional third arg "--daemon" detaches the process so the terminal
        # is not blocked.
        import asyncio
        from web_ui import WebUI, choose_server

        daemon = len(sys.argv) == 4 and sys.argv[3] == "--daemon"
        if daemon:
            _run_daemon(sys.argv[2])
            return

        server_url = choose_server()
        ui = WebUI(sys.argv[2], server_url)
        asyncio.run(ui.run())
    elif command == "group":
        cmd_group(sys.argv[2:])
    elif command == "server":
        cmd_server(sys.argv[2:])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
