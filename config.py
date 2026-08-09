"""Configuration loader for simplchat.

Loads server settings from a TOML file (config.toml) using Python's built-in
tomllib module, so no extra dependencies are needed.

The config file can be copied between devices to share the same settings.
"""

import os
import tomllib
from dataclasses import dataclass

# Default location of the config file, resolved relative to this module so it
# works whether the app is run from the project dir or via the installed
# 'simplchat-server' launcher.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.toml")


@dataclass
class ServerConfig:
    """Server settings loaded from the TOML config file.

    Attributes:
        host: Host the server listens on.
        port: Port the server listens on.
        domain: Public domain address clients use to reach the server.
        tls_enabled: Whether TLS (wss://) is enabled.
        cert_file: Path to the TLS certificate.
        key_file: Path to the TLS private key.
    """

    host: str = "localhost"
    port: int = 8765
    domain: str = "localhost"
    tls_enabled: bool = False
    cert_file: str = "cert.pem"
    key_file: str = "key.pem"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> ServerConfig:
    """Load server settings from a TOML file.

    Args:
        path: Path to the TOML config file.

    Returns:
        A ServerConfig with the loaded settings. Falls back to defaults if
        the file is missing or a section is absent.
    """
    config = ServerConfig()

    # If the config file doesn't exist, use defaults.
    if not os.path.exists(path):
        return config

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Read the [server] section.
    server = data.get("server", {})
    config.host = server.get("host", config.host)
    config.port = server.get("port", config.port)
    config.domain = server.get("domain", config.domain)

    # Read the [tls] section.
    tls = data.get("tls", {})
    config.tls_enabled = tls.get("tls_enabled", config.tls_enabled)
    config.cert_file = tls.get("cert_file", config.cert_file)
    config.key_file = tls.get("key_file", config.key_file)

    return config
