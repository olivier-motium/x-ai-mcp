"""X E2E encrypted DM crypto module.

Reverse-engineered from x.com's ondemand.DirectMessagesCrypto JS chunk.

Protocol (as implemented by X's web client):
- Device keypair: ECDH NIST P-256 (non-exportable private key in browser)
- Conversation key: AES-GCM-256 (random, per-conversation)
- Conversation key wrapping: ECDH ephemeral + SHA-256 KDF + AES-GCM-128
- Message encryption: AES-GCM-256 with 12-byte random IV
- Encrypted conversation IDs start with "e" (e.g., "e1234-5678")

Key registry API (requires X Premium):
- POST keyregistry/register — body: {registration_id, identity_key}, header: X-Client-UUID
- GET keyregistry/extract_public_keys/{userId} — returns {public_keys: [{identity_key, ...}]}
- DELETE keyregistry/delete/{registrationToken}

References:
- mjg59's analysis: https://mjg59.dreamwidth.org/66791.html
- X help docs: https://help.x.com/en/using-x/encrypted-direct-messages
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

from . import config


class E2ECryptoError(Exception):
    pass


def _ensure_cryptography():
    """Import cryptography lazily — only needed for E2E features."""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def is_encrypted_conversation(conversation_id: str) -> bool:
    """Check if a conversation ID indicates E2E encryption (starts with 'e')."""
    return conversation_id.startswith("e")


class DeviceKeyManager:
    """Manages device P-256 key pair for E2E encrypted DMs.

    Matches X web client's key generation:
    - ECDH P-256 keypair
    - UUID v4 device ID
    - SPKI format for public key (identity_key in API)
    """

    def __init__(self, keys_path: Path | None = None) -> None:
        self._keys_path = keys_path or config.X_KEYS_PATH
        self._private_key = None
        self._public_key = None
        self._device_id: str | None = None
        self._load_keys()

    def _load_keys(self) -> None:
        """Load existing device keys from disk."""
        if not self._keys_path.exists():
            return
        try:
            data = json.loads(self._keys_path.read_text())
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            self._private_key = load_pem_private_key(
                data["private_key_pem"].encode(), password=None
            )
            self._public_key = self._private_key.public_key()
            self._device_id = data.get("device_id")
        except Exception:
            pass

    def generate_keys(self) -> None:
        """Generate a new P-256 key pair and save to disk."""
        if not _ensure_cryptography():
            raise E2ECryptoError("cryptography package required")

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat,
        )

        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()
        self._device_id = str(uuid.uuid4())

        priv_pem = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        pub_spki = self._public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        data = {
            "private_key_pem": priv_pem,
            "identity_key_b64": base64.b64encode(pub_spki).decode(),
            "device_id": self._device_id,
        }
        self._keys_path.write_text(json.dumps(data, indent=2))

    @property
    def has_keys(self) -> bool:
        return self._private_key is not None

    @property
    def device_id(self) -> str:
        if not self._device_id:
            raise E2ECryptoError("No device keys loaded")
        return self._device_id

    @property
    def identity_key_b64(self) -> str:
        """Public key in SPKI/DER format, base64-encoded (matches X's identity_key)."""
        if not self._public_key:
            raise E2ECryptoError("No device keys loaded")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pub_spki = self._public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pub_spki).decode()

    def registration_body(self) -> dict:
        """Build the registration request body for keyregistry/register."""
        import random
        return {
            "registration_id": random.randint(10000, 99999),
            "identity_key": self.identity_key_b64,
        }

    def decrypt_conversation_key(self, encrypted_conv_key_b64: str) -> bytes:
        """Decrypt an encrypted_conversation_key from the API response.

        X's protocol (from DirectMessagesCrypto.js):
        1. First 65 bytes = sender's ephemeral uncompressed P-256 public key
        2. Remaining bytes = AES-GCM-128 ciphertext of the conversation key
        3. KDF: SHA-256(ECDH_shared_secret || [0,0,0,1] || ephemeral_pubkey)
        4. Split KDF output: first 16 bytes = AES key, next 16 bytes = IV
        """
        if not self._private_key:
            raise E2ECryptoError("No device keys loaded")
        if not _ensure_cryptography():
            raise E2ECryptoError("cryptography package required")

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = base64.b64decode(encrypted_conv_key_b64)
        # First 65 bytes: uncompressed P-256 point (0x04 || x || y)
        ephemeral_pub_raw = raw[:65]
        ciphertext = raw[65:]

        # Import ephemeral public key
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_raw
        )

        # ECDH to derive shared secret
        shared_secret = self._private_key.exchange(ec.ECDH(), ephemeral_pub)

        # KDF: SHA-256(shared_secret || [0,0,0,1] || ephemeral_pubkey)
        counter = b"\x00\x00\x00\x01"
        kdf_input = shared_secret + counter + ephemeral_pub_raw
        kdf_output = hashlib.sha256(kdf_input).digest()

        # Split: first 16 bytes = AES key, next 16 = IV
        aes_key = kdf_output[:16]
        iv = kdf_output[16:32]

        # AES-GCM-128 decrypt
        aesgcm = AESGCM(aes_key)
        conversation_key_raw = aesgcm.decrypt(iv, ciphertext, None)
        return conversation_key_raw


def decrypt_message(ciphertext_b64: str, conversation_key: bytes) -> str:
    """Decrypt a message using the conversation's AES-GCM-256 key.

    Format: base64(IV[12] || AES-GCM-256(plaintext))
    """
    if not _ensure_cryptography():
        raise E2ECryptoError("cryptography package required")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:12]
    ciphertext = raw[12:]

    aesgcm = AESGCM(conversation_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8", errors="replace")


def encrypt_message(plaintext: str, conversation_key: bytes) -> str:
    """Encrypt a message using the conversation's AES-GCM-256 key.

    Returns: base64(IV[12] || AES-GCM-256(plaintext))
    """
    if not _ensure_cryptography():
        raise E2ECryptoError("cryptography package required")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(conversation_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(iv + ciphertext).decode()
