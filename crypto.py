import base64
import os
import time
import keyring
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from protocol import Message

SERVICE = "simplchat"

# Number of PBKDF2 iterations for password-derived keys. Higher is slower but
# more resistant to brute-force. 600k is a reasonable modern default.
PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2.

    Args:
        password: The user's password.
        salt: A random salt (stored alongside the encrypted key).

    Returns:
        A 32-byte key suitable for AES-GCM.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_private_key(private_pem: str, password: str) -> tuple[str, str]:
    """Encrypt a private key PEM with a password-derived key.

    Args:
        private_pem: The private key as a PEM string.
        password: The user's password.

    Returns:
        A tuple of (encrypted_b64, salt_b64). The salt is needed to derive
        the same key again when decrypting.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, private_pem.encode(), None)
    # Bundle nonce + ciphertext so we can decrypt later.
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode(), base64.b64encode(salt).decode()


def decrypt_private_key(encrypted_b64: str, salt_b64: str, password: str) -> str:
    """Decrypt a private key PEM that was encrypted with encrypt_private_key.

    Args:
        encrypted_b64: The encrypted blob (base64).
        salt_b64: The salt (base64).
        password: The user's password.

    Returns:
        The original private key PEM string.

    Raises:
        InvalidTag: If the password is wrong (decryption fails).
    """
    blob = base64.b64decode(encrypted_b64)
    salt = base64.b64decode(salt_b64)
    key = derive_key(password, salt)
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()

# Keygen function
def generate_keypair() -> tuple[str, str]:
    """Returns (public_pem, private_pem)"""
    # RSA is used because it supports direct encrypt/decrypt with a public key.
    # (ECC keys have no .encrypt()/.decrypt() methods.)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return public_pem, private_pem

# Storing the keygen in a private folder
def store_private_key(username: str, private_pem: str) -> None:
    keyring.set_password(SERVICE, f"{username}_private", private_pem)
# Loading the keys
def load_private_key(username: str) -> str:
    """Return the user's RSA private key as a PEM string.

    Returns the raw PEM string (not a key object) so it can be passed
    directly to decrypt_message, keeping the API consistent.
    """
    pem = keyring.get_password(SERVICE, f"{username}_private")
    if pem is None:
        raise KeyError(f"No private key found for user '{username}'")
    return pem

# Decrypting received messages, and the wrapped keys
def decrypt_message(
    payload: dict,
    username: str,
    private_key_pem: str,
    sender_public_pem: str,
) -> bytes:
    """Decrypt a message for a specific recipient and verify the sender.

    Args:
        payload: The message payload produced by encrypt_for_recipients.
        username: The recipient's own username, used to find their wrapped key.
        private_key_pem: The recipient's RSA private key as a PEM string
            (for unwrapping the DEK).
        sender_public_pem: The sender's ECDSA public key (for signature check).

    Returns:
        The decrypted plaintext bytes.

    Raises:
        KeyError: If this recipient has no wrapped key in the payload.
        ValueError: If the sender's signature fails to verify.
    """
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    # Look up THIS recipient's wrapped key by username (not a hardcoded index).
    # This is what makes group messaging work: each recipient finds their own key.
    if username not in payload["wrapped_keys"]:
        raise KeyError(f"No wrapped key found for recipient '{username}'")
    wrapped = base64.b64decode(payload["wrapped_keys"][username])

    # Load the recipient's RSA private key from PEM.
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")

    # RSA-OAEP: unwrap the DEK with the recipient's private key
    dek = private_key.decrypt(wrapped, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ))
    plaintext = AESGCM(dek).decrypt(nonce, ciphertext, None)

    # Verify the sender's signature
    if not verify_signature(sender_public_pem, plaintext, payload["signature"]):
        raise ValueError("Signature verification failed — message may be forged or tampered")
    return plaintext

# Encrypting the message for the recipients with their keys

def generate_signing_keypair() -> tuple[str, str]:
    """Returns (public_pem, private_pem) for ECDSA signing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return public_pem, private_pem

def sign_message(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    """Sign a message with the sender's ECDSA private key."""
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()

def verify_signature(public_pem: str, message: bytes, signature_b64: str) -> bool:
    """Verify a signature against the sender's ECDSA public key."""
    pub = serialization.load_pem_public_key(public_pem.encode())
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise TypeError("Expected an ECDSA public key")
    signature = base64.b64decode(signature_b64)
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def store_signing_key(username: str, private_pem: str) -> None:
    keyring.set_password(SERVICE, f"{username}_signing", private_pem)

def load_signing_key(username: str) -> str:
    """Return the user's ECDSA signing key as a PEM string.

    Returns the raw PEM string (not a key object) so it can be passed
    directly to encrypt_for_recipients, keeping the API consistent.
    """
    pem = keyring.get_password(SERVICE, f"{username}_signing")
    if pem is None:
        raise KeyError(f"No signing key found for user '{username}'")
    return pem

def encrypt_for_recipients(
    message: bytes,
    recipients: dict[str, str],
    sender_signing_key_pem: str,
    sender_public_pem: str,
) -> dict:
    """Encrypt once, wrap the key for each recipient, and sign the message.

    Args:
        message: The plaintext bytes to encrypt.
        recipients: Mapping of {username: public_pem} for every recipient.
        sender_signing_key_pem: The sender's ECDSA private key as a PEM string
            (used for signing).
        sender_public_pem: The sender's ECDSA public key (sent for verification).

    Returns:
        A JSON-serializable dict containing the ciphertext, nonce, per-recipient
        wrapped keys, the signature, and the sender's public key.
    """
    # Load the sender's signing key from PEM (matches how public keys are passed).
    signing_key = serialization.load_pem_private_key(
        sender_signing_key_pem.encode(), password=None
    )
    if not isinstance(signing_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Expected an ECDSA signing key")

    # Sign the PLAINTEXT before encrypting (sign-then-encrypt).
    # This binds the signature to the actual content, so tampering is detected.
    signature = sign_message(signing_key, message)

    # Random symmetric key (the DEK) - 256-bit AES key
    dek = os.urandom(32)
    # Unique nonce per message - GCM requires a fresh nonce every time
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, message, None)

    # Wrap the DEK for each recipient with their public key.
    # wrapped_keys is a dict keyed by username so each recipient can find
    # their own entry when decrypting.
    wrapped = {}
    for username, pem in recipients.items():
        pub = serialization.load_pem_public_key(pem.encode())
        # Narrow the generic type to RSA so the type checker knows .encrypt() exists
        if not isinstance(pub, rsa.RSAPublicKey):
            raise TypeError(f"Expected an RSA public key for '{username}'")
        # RSA-OAEP: encrypt the DEK with the recipient's public key
        wrapped[username] = base64.b64encode(pub.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )).decode()

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "wrapped_keys": wrapped,
        "signature": signature,
        "sender_public": sender_public_pem,
    }

def public_key_from_private(private_pem: str) -> str:
    """Derive the public key PEM from a private key PEM.

    This works for both RSA and ECDSA keys. It is used to publish a user's
    public key without storing it separately.

    Args:
        private_pem: The private key as a PEM string.

    Returns:
        The corresponding public key as a PEM string.
    """
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public_key = private_key.public_key()
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_key_fingerprint(public_pem: str) -> str:
    """Return a short, human-comparable fingerprint of a public key."""
    # Hash the raw public key bytes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_pem.encode())
    # Take the first 8 bytes and format as hex, grouped for readability
    hex_digest = digest.finalize()[:8].hex()
    return ":".join(hex_digest[i:i+2] for i in range(0, len(hex_digest), 2))


def build_message(
    sender: str,
    recipients: dict[str, str],
    text: str,
    sender_signing_key_pem: str,
    sender_public_pem: str,
) -> "Message":
    """Build a fully-formed protocol Message from plaintext.

    This is a convenience wrapper that ties the crypto layer to the protocol
    layer: it encrypts and signs the text, then wraps the result in a Message
    with the sender, recipients, and a fresh timestamp.

    Args:
        sender: The sender's username.
        recipients: Mapping of {username: public_pem} for every recipient.
        text: The plaintext message to send.
        sender_signing_key_pem: The sender's ECDSA signing key (PEM string).
        sender_public_pem: The sender's ECDSA public key (PEM string).

    Returns:
        A protocol.Message ready to be serialized and sent.
    """
    # Encrypt and sign the plaintext.
    payload = encrypt_for_recipients(
        text.encode(),
        recipients,
        sender_signing_key_pem,
        sender_public_pem,
    )

    # Wrap the crypto payload in a protocol Message with metadata.
    return Message(
        sender=sender,
        recipients=list(recipients.keys()),
        timestamp=int(time.time()),
        payload=payload,
    )