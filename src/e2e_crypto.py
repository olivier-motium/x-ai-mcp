"""X E2E encrypted DM crypto module.

Handles device key management and message decryption for X's encrypted DMs.

X's E2E DM protocol:
- Each device generates a NIST P-256 (secp256r1) key pair
- Public key registered with X's key registry
- Per-conversation AES key encrypts message content
- Conversation key is ECDH-derived between sender and recipient devices
- PIN encrypts private key backup on X's servers for cross-device recovery

References:
- mjg59's analysis: https://mjg59.dreamwidth.org/66791.html
- X help docs: https://help.x.com/en/using-x/encrypted-direct-messages
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

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


class DeviceKeyManager:
    """Manages device P-256 key pair for E2E encrypted DMs."""

    def __init__(self, keys_path: Path | None = None) -> None:
        self._keys_path = keys_path or config.X_KEYS_PATH
        self._private_key = None
        self._public_key = None
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
        except Exception:
            pass

    def generate_keys(self) -> None:
        """Generate a new P-256 key pair and save to disk."""
        if not _ensure_cryptography():
            raise E2ECryptoError("cryptography package required: pip install cryptography")

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()

        # Save to disk
        priv_pem = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        pub_pem = self._public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        pub_raw = self._public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        data = {
            "private_key_pem": priv_pem,
            "public_key_pem": pub_pem,
            "public_key_b64": base64.b64encode(pub_raw).decode(),
        }
        self._keys_path.write_text(json.dumps(data, indent=2))

    @property
    def has_keys(self) -> bool:
        return self._private_key is not None

    @property
    def public_key_b64(self) -> str:
        if not self._public_key:
            raise E2ECryptoError("No device keys loaded")
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        pub_raw = self._public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return base64.b64encode(pub_raw).decode()

    def derive_shared_secret(self, peer_public_key_b64: str) -> bytes:
        """Derive shared secret via ECDH with a peer's public key."""
        if not self._private_key:
            raise E2ECryptoError("No device keys loaded")

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        peer_raw = base64.b64decode(peer_public_key_b64)
        peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_raw
        )
        shared_key = self._private_key.exchange(ec.ECDH(), peer_key)
        return shared_key


def derive_pin_key(pin: str, salt: bytes | None = None) -> bytes:
    """Derive encryption key from PIN for private key backup.

    X uses the PIN to encrypt the private key before storing it on their
    servers, allowing recovery on new devices.
    """
    if salt is None:
        salt = b"x-encrypted-dm-pin"
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100000, dklen=32)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    if not _ensure_cryptography():
        raise E2ECryptoError("cryptography package required")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def decrypt_aes_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-CTR ciphertext (used for some message types)."""
    if not _ensure_cryptography():
        raise E2ECryptoError("cryptography package required")

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    """HKDF-SHA256 key derivation."""
    if not _ensure_cryptography():
        raise E2ECryptoError("cryptography package required")

    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def try_decrypt_message(
    encrypted_data: dict[str, Any],
    conversation_key: bytes | None = None,
    device_key_manager: DeviceKeyManager | None = None,
) -> str | None:
    """Attempt to decrypt an encrypted DM message.

    The encrypted message format varies between X versions. This function
    tries multiple approaches.

    Args:
        encrypted_data: The encrypted message payload from the API
        conversation_key: Pre-derived conversation AES key (if available)
        device_key_manager: Device key manager for ECDH derivation

    Returns:
        Decrypted plaintext or None if decryption fails
    """
    # Extract encrypted payload
    ciphertext_b64 = encrypted_data.get("ciphertext") or encrypted_data.get("text")
    if not ciphertext_b64:
        return None

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        # Not base64 — might be plaintext
        return ciphertext_b64

    # If we have a conversation key, try direct AES decryption
    if conversation_key:
        # Try AES-GCM: first 12 bytes = nonce, rest = ciphertext + tag
        if len(ciphertext) > 28:  # 12 nonce + 16 tag minimum
            try:
                nonce = ciphertext[:12]
                ct = ciphertext[12:]
                plaintext = decrypt_aes_gcm(conversation_key, nonce, ct)
                return plaintext.decode("utf-8", errors="replace")
            except Exception:
                pass

        # Try AES-CTR: first 16 bytes = nonce
        if len(ciphertext) > 16:
            try:
                nonce = ciphertext[:16]
                ct = ciphertext[16:]
                plaintext = decrypt_aes_ctr(conversation_key, nonce, ct)
                return plaintext.decode("utf-8", errors="replace")
            except Exception:
                pass

    # If we have device keys and the message includes an encrypted conversation key
    if device_key_manager and device_key_manager.has_keys:
        enc_conv_key = encrypted_data.get("encrypted_conversation_key")
        sender_public_key = encrypted_data.get("sender_public_key")

        if enc_conv_key and sender_public_key:
            try:
                # Derive shared secret via ECDH
                shared = device_key_manager.derive_shared_secret(sender_public_key)
                # Derive conversation key from shared secret
                conv_key = hkdf_sha256(shared, b"x-dm-conversation-key")
                # Decrypt the conversation key
                enc_key_bytes = base64.b64decode(enc_conv_key)
                nonce = enc_key_bytes[:12]
                ct = enc_key_bytes[12:]
                actual_conv_key = decrypt_aes_gcm(conv_key, nonce, ct)
                # Now decrypt the message with the conversation key
                msg_ct = base64.b64decode(ciphertext_b64)
                msg_nonce = msg_ct[:12]
                msg_body = msg_ct[12:]
                plaintext = decrypt_aes_gcm(actual_conv_key, msg_nonce, msg_body)
                return plaintext.decode("utf-8", errors="replace")
            except Exception:
                pass

    return None


def format_encrypted_status(msg_data: dict) -> str:
    """Describe the encryption status of a message for display."""
    if msg_data.get("dm_secret_conversations_enabled"):
        return "[E2E ENCRYPTED]"
    return ""
