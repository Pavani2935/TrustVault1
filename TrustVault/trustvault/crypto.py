"""Envelope encryption for document bytes.

* Every stored version gets its own random 256-bit data key (DEK).
* The file is encrypted with AES-256-GCM under the DEK. The associated data binds the
  ciphertext to its document id, version id and plaintext hash, so ciphertext copied
  from one row into another (a database-level swap) fails to decrypt.
* The DEK is wrapped with a key-encryption key (KEK) derived via HKDF from
  TRUSTVAULT_MASTER_KEY, which lives only in the host's secret store, never in the DB.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE = 12


class IntegrityError(Exception):
    """Ciphertext, key or binding data did not authenticate."""


def derive_key(secret: str, purpose: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"trustvault/v1",
                info=purpose.encode()).derive(secret.encode())


def key_fingerprint(key: bytes) -> str:
    return "k-" + hashlib.sha256(b"fingerprint" + key).hexdigest()[:12]


class Vault:
    def __init__(self, master_secret: str):
        self._kek = derive_key(master_secret, "file-key-encryption")
        self.key_id = key_fingerprint(self._kek)

    @staticmethod
    def _aad(document_id: str, version_id: str, sha256: str) -> bytes:
        return f"trustvault|{document_id}|{version_id}|{sha256}".encode()

    def encrypt(self, plaintext: bytes, document_id: str, version_id: str, sha256: str) -> tuple[bytes, bytes]:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE)
        ciphertext = nonce + AESGCM(dek).encrypt(nonce, plaintext, self._aad(document_id, version_id, sha256))
        wrap_nonce = os.urandom(NONCE)
        wrapped = wrap_nonce + AESGCM(self._kek).encrypt(wrap_nonce, dek, f"dek|{version_id}".encode())
        return wrapped, ciphertext

    def decrypt(self, wrapped: bytes, ciphertext: bytes, document_id: str, version_id: str,
                sha256: str, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise IntegrityError(f"stored with key {key_id}, server holds {self.key_id}")
        try:
            wrapped, ciphertext = bytes(wrapped), bytes(ciphertext)
            dek = AESGCM(self._kek).decrypt(wrapped[:NONCE], wrapped[NONCE:], f"dek|{version_id}".encode())
            plaintext = AESGCM(dek).decrypt(ciphertext[:NONCE], ciphertext[NONCE:],
                                            self._aad(document_id, version_id, sha256))
        except (InvalidTag, ValueError) as exc:
            raise IntegrityError("ciphertext failed authentication") from exc
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), sha256):
            raise IntegrityError("plaintext hash mismatch")
        return plaintext
