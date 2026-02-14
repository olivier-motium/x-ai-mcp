"""X E2E encrypted DM crypto module — XChat protocol (June 2025+).

Protocol (reverse-engineered from X's web client):
- Device keypair: ECDH NIST P-256 (registered via GraphQL AddXChatPublicKey)
- Conversation key: 32-byte random (per-conversation)
- Conversation key wrapping: ECDH ephemeral P-256 + SHA-256 KDF + AES-GCM-128
- Message encryption: NaCl secretbox (XSalsa20-Poly1305, 24-byte nonce)
- Decrypted message payload: Thrift TBinaryProtocol struct containing text
- Encrypted conversation IDs start with "e" (e.g., "e1234-5678")

Key management:
- GraphQL: GetPublicKeys, AddXChatPublicKey, GetInitialXChatPageQuery
- Private key backup: Juicebox PIN-based recovery (4 HSM realms)
- Messages: Thrift TBinaryProtocol, base64-encoded
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from pathlib import Path

from . import config

log = logging.getLogger(__name__)


class E2ECryptoError(Exception):
    pass


def _ensure_cryptography():
    """Import cryptography lazily — only needed for E2E features."""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _b64url_decode(s: str) -> bytes:
    """Decode base64url (no padding) to bytes."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def is_encrypted_conversation(conversation_id: str) -> bool:
    """Check if a conversation ID indicates XChat E2E encryption.

    XChat conversations use colon-separated user IDs (e.g., '123:456').
    Regular DM conversations use dash-separated IDs (e.g., '123-456').
    """
    return ":" in conversation_id


def load_private_key_from_env():
    """Load the ECDH private key from the X_PRIVATE_KEY_D env var.

    The value is the base64url-encoded "d" parameter from the JWK
    (the 32-byte P-256 private scalar).
    """
    d_b64url = config.X_PRIVATE_KEY_D
    if not d_b64url:
        return None
    if not _ensure_cryptography():
        return None

    from cryptography.hazmat.primitives.asymmetric import ec

    d_bytes = _b64url_decode(d_b64url)
    d_int = int.from_bytes(d_bytes, "big")
    return ec.derive_private_key(d_int, ec.SECP256R1())


class DeviceKeyManager:
    """Manages device P-256 key pair for E2E encrypted DMs."""

    def __init__(self, keys_path: Path | None = None) -> None:
        self._keys_path = keys_path or config.X_KEYS_PATH
        self._private_key = None
        self._public_key = None
        self._device_id: str | None = None
        self._load_keys()

    def _load_keys(self) -> None:
        """Load device keys — from env var first, then from disk."""
        # Try env var (base64url "d" parameter)
        key = load_private_key_from_env()
        if key:
            self._private_key = key
            self._public_key = key.public_key()
            self._device_id = "env-key"
            return

        # Fall back to disk
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
        """Public key in SPKI/DER format, base64-encoded."""
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
        """Decrypt an encrypted conversation key.

        Format: ephemeral_pubkey[65] || AES-GCM-128(conversation_key)
        KDF: SHA-256(ECDH_shared || counter[4] || ephemeral_pubkey)
        Split: key = kdf[:16], iv = kdf[16:32]
        """
        if not self._private_key:
            raise E2ECryptoError("No device keys loaded")
        if not _ensure_cryptography():
            raise E2ECryptoError("cryptography package required")

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = base64.b64decode(encrypted_conv_key_b64)
        ephemeral_pub_raw = raw[:65]
        ciphertext = raw[65:]

        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_raw
        )

        shared_secret = self._private_key.exchange(ec.ECDH(), ephemeral_pub)

        counter = b"\x00\x00\x00\x01"
        kdf_input = shared_secret + counter + ephemeral_pub_raw
        kdf_output = hashlib.sha256(kdf_input).digest()

        aes_key = kdf_output[:16]
        iv = kdf_output[16:32]

        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(iv, ciphertext, None)


# Module-level singleton for the key manager
_key_manager: DeviceKeyManager | None = None


def get_key_manager() -> DeviceKeyManager:
    """Get or create the singleton DeviceKeyManager."""
    global _key_manager
    if _key_manager is None:
        _key_manager = DeviceKeyManager()
    return _key_manager


def decrypt_message_content(
    enc_text: str, key_version: str, conversation_key: bytes | None,
) -> str:
    """Decrypt or decode XChat message content to plain text.

    Two formats depending on key_version:
    - key_version set: NaCl secretbox encrypted → decrypt → inner Thrift → text
    - key_version empty: content is already a Thrift struct (raw or base64) → parse directly

    Returns the extracted message text string.
    """
    from .thrift_decoder import decode_struct

    if key_version and conversation_key:
        # Encrypted: NaCl secretbox → inner Thrift struct
        import nacl.secret

        raw = base64.b64decode(enc_text)
        box = nacl.secret.SecretBox(conversation_key)
        plaintext = box.decrypt(raw)
        fields, _ = decode_struct(plaintext)
    else:
        # Unencrypted: content IS the Thrift struct (raw bytes or base64)
        raw = enc_text.encode("latin-1") if isinstance(enc_text, str) else enc_text
        # Check if it starts with Thrift struct marker (0x0c = T_STRUCT)
        if raw and raw[0] == 0x0C:
            fields, _ = decode_struct(raw)
        else:
            # Try base64 decode first
            try:
                decoded = base64.b64decode(enc_text)
                if decoded and decoded[0] == 0x0C:
                    fields, _ = decode_struct(decoded)
                else:
                    return enc_text  # Plain text fallback
            except Exception:
                return enc_text  # Plain text fallback

    return _extract_text_from_content(fields)


def _extract_text_from_content(fields: dict) -> str:
    """Extract message text from inner Thrift content struct.

    Structure:
      field 1 (struct) → field 1 (struct) → field 1 (string) = text
      field 1 (struct) → field 4 (struct) → field 2 (string) = quote reply
      field 1 (struct) → field 1 (struct) → field 3 (list)  = attachments
    """
    content = fields.get(1, {})
    if not isinstance(content, dict):
        return "[unknown content format]"

    # Regular text message: content[1][1]
    msg_struct = content.get(1, {})
    if isinstance(msg_struct, dict):
        text = msg_struct.get(1, "")
        if isinstance(text, str) and text:
            return text
        # Image/attachment with no text
        attachments = msg_struct.get(3, [])
        if attachments:
            att_names = []
            for att in attachments:
                if isinstance(att, dict):
                    inner = att.get(1, {})
                    if isinstance(inner, dict):
                        att_names.append(inner.get(6, "attachment"))
            return f"[media: {', '.join(att_names)}]" if att_names else "[attachment]"

    # Quote reply: content[4][2]
    quote = content.get(4, {})
    if isinstance(quote, dict):
        ref_id = quote.get(1, "")
        text = quote.get(2, "")
        if isinstance(text, str) and text:
            return f"[reply to {ref_id}] {text}" if ref_id else text

    return "[empty message]"
