# simplchat

An end-to-end encrypted chat application. Messages are encrypted and signed on the client before they ever reach the server, so the server only ever sees ciphertext.

## Features

- **End-to-end encryption** — hybrid RSA-OAEP + AES-GCM, with ECDSA signing for authenticity
- **Group messaging** — encrypt once, deliver to many recipients
- **Replay protection** — rejects replayed or stale messages
- **Encrypted message history** — stored on the server as ciphertext, decrypted only on the client
- **Web UI** — a local browser interface that does all crypto in Python
- **CLI chat** — a terminal client
- **Server registry** — choose from a list of known servers
- **TOFU identity** — public keys verified via fingerprints
- **TLS support** — optional wss:// transport

## Installation

Requires Python 3.14+ and either `uv` or `pip`.

```bash
./install.sh
```

This installs three commands:

| Command | Purpose |
|---------|---------|
| `simplchat` | CLI (register, chat, web, group, server) |
| `simplchat-server` | Relay server |
| `simplchat-web` | Local web UI for a client |

## Usage

### 1. Start the server

```bash
simplchat-server
```

Server settings (host, port, domain, TLS) live in `config.toml`.

### 2. Register a user

```bash
simplchat register alice
```

### 3. Chat

**Web UI** (recommended):

```bash
simplchat-web alice
```

Then open the printed URL in a browser.

**CLI:**

```bash
simplchat chat alice
```

Type `recipient: message` to send.

### Managing servers

```bash
simplchat server add "My Server" "wss://chat.example.com:8765"
simplchat server list
```

### Managing groups

```bash
simplchat group create family alice,bob,carol
simplchat group list
```

## License

MIT
