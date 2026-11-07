"""Client-side encryption for the chat room.

Key   = Argon2id(passphrase, salt = SHA-256("supabase-chat-v1:" + room))
Cipher = AES-256-GCM with a fresh random 12-byte nonce per message.
AAD    = room + username, so a message can't be silently moved to another
         room or re-attributed to another user without failing decryption.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

SALT_PREFIX = b"supabase-chat-v1:"


class DecryptionError(Exception):
    """Wrong passphrase, or the message was tampered with."""


def derive_key(passphrase: str, room: str) -> bytes:
    """Derive a 32-byte AES key. Deliberately slow (~0.5 s) to resist guessing."""
    salt = hashlib.sha256(SALT_PREFIX + room.encode()).digest()
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=64 * 1024,  # 64 MiB
    )
    return kdf.derive(passphrase.encode())


def _aad(room: str, username: str) -> bytes:
    return f"{room}\x00{username}".encode()


class RoomCipher:
    def __init__(self, key: bytes, room: str):
        self._aes = AESGCM(key)
        self.room = room

    def encrypt(self, username: str, plaintext: str) -> tuple[str, str]:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode(), _aad(self.room, username))
        return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()

    def decrypt(self, username: str, nonce_b64: str, ciphertext_b64: str) -> str:
        try:
            nonce = base64.b64decode(nonce_b64)
            ct = base64.b64decode(ciphertext_b64)
            pt = self._aes.decrypt(nonce, ct, _aad(self.room, username))
            return pt.decode()
        except (InvalidTag, ValueError) as exc:
            raise DecryptionError from exc
