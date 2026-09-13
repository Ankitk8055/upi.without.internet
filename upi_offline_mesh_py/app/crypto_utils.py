"""
crypto_utils.py
----------------
Python port of ServerKeyHolder.java + HybridCryptoService.java

Wire format (identical layout to the Java version):
    [256 bytes RSA-OAEP-encrypted AES key][12 bytes GCM IV][AES-GCM ciphertext + 16-byte tag]

Why hybrid encryption?
RSA-2048 can only safely encrypt ~245 bytes. Our JSON payload can be bigger,
so we generate a random AES-256 key per packet, encrypt the payload with
AES-256-GCM (fast + authenticated), and only RSA-encrypt the small AES key.
This is the same pattern TLS uses.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE_BITS = 2048
RSA_CIPHERTEXT_LEN = RSA_KEY_SIZE_BITS // 8  # 256 bytes
AES_KEY_LEN = 32  # 256-bit AES key
GCM_IV_LEN = 12  # 96-bit nonce, the standard/recommended size for GCM


class ServerKeyHolder:
    """
    Generates a fresh RSA-2048 keypair on startup, exactly like the Java
    version (ServerKeyHolder.java). In production this would be swapped
    for a key loaded from an HSM / KMS, with the public key distributed
    to client devices ahead of time.
    """

    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE_BITS,
        )
        self._public_key = self._private_key.public_key()

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key

    def public_key_base64(self) -> str:
        """Return the DER-encoded public key, base64 text (for /api/server-key)."""
        import base64
        der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(der).decode("ascii")


class HybridCryptoService:
    """
    RSA-OAEP + AES-256-GCM encrypt/decrypt, plus the ciphertext hashing used
    for idempotency. Mirrors HybridCryptoService.java exactly in wire format
    so a real client implementation (Android/Kotlin, or another Python
    client) can interoperate.
    """

    def __init__(self, key_holder: ServerKeyHolder):
        self._keys = key_holder

    # ---------- encryption (simulates what the sender's phone would do) ----------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        1. Generate a fresh AES-256 key for this packet.
        2. Encrypt plaintext with AES-256-GCM (random 12-byte IV).
        3. Encrypt just the AES key with RSA-OAEP(SHA-256) using the
           server's public key.
        4. Concatenate: [RSA-encrypted AES key][IV][AES ciphertext+tag]
        """
        aes_key = os.urandom(AES_KEY_LEN)
        iv = os.urandom(GCM_IV_LEN)

        aesgcm = AESGCM(aes_key)
        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, associated_data=None)

        encrypted_aes_key = self._keys.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        if len(encrypted_aes_key) != RSA_CIPHERTEXT_LEN:
            raise ValueError("Unexpected RSA ciphertext length")

        return encrypted_aes_key + iv + ciphertext_and_tag

    # ---------- decryption (what the backend does on ingest) ----------

    def decrypt(self, blob: bytes) -> bytes:
        """
        Inverse of encrypt(). Raises an exception (ValueError / InvalidTag)
        if the blob is malformed OR if the GCM authentication tag doesn't
        verify — i.e. if the ciphertext was tampered with in transit.
        This exception is what BridgeIngestionService catches to return
        outcome=INVALID instead of crashing or silently corrupting data.
        """
        if len(blob) < RSA_CIPHERTEXT_LEN + GCM_IV_LEN + 16:
            raise ValueError("Ciphertext blob too short to be valid")

        encrypted_aes_key = blob[:RSA_CIPHERTEXT_LEN]
        iv = blob[RSA_CIPHERTEXT_LEN:RSA_CIPHERTEXT_LEN + GCM_IV_LEN]
        ciphertext_and_tag = blob[RSA_CIPHERTEXT_LEN + GCM_IV_LEN:]

        aes_key = self._keys.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm = AESGCM(aes_key)
        # Raises cryptography.exceptions.InvalidTag on tampering.
        plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, associated_data=None)
        return plaintext

    # ---------- idempotency helper ----------

    @staticmethod
    def hash_ciphertext(blob: bytes) -> str:
        """
        SHA-256 of the raw ciphertext bytes, hex-encoded.

        We hash the *ciphertext*, not the packetId and not the decrypted
        payload:
          - packetId can be rewritten by a malicious/broken intermediate.
          - Hashing before decrypting avoids spending CPU on RSA for
            packets we're about to drop as duplicates anyway.
          - AES-GCM is deterministic for a fixed (key, iv, plaintext), so
            two legitimate deliveries of the *same* signed payment produce
            byte-identical ciphertext, and therefore the same hash.
        """
        return hashlib.sha256(blob).hexdigest()