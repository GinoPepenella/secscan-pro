"""
Encryption utilities for sensitive data like SSH passwords and private keys.
Uses Fernet symmetric encryption (AES-128 in CBC mode with HMAC).
"""

from cryptography.fernet import Fernet
from app.core.config import settings
from typing import Optional
import base64
import hashlib


class EncryptionManager:
    """Manages encryption and decryption of sensitive data."""

    def __init__(self):
        # Generate a key from the SECRET_KEY setting
        # In production, use a proper key management system
        key = self._derive_key(settings.SECRET_KEY)
        self.cipher = Fernet(key)

    @staticmethod
    def _derive_key(secret: str) -> bytes:
        """Derive a Fernet-compatible key from a secret string."""
        # Use SHA256 to create a 32-byte key
        hash_digest = hashlib.sha256(secret.encode()).digest()
        # Fernet requires base64-encoded 32-byte key
        return base64.urlsafe_b64encode(hash_digest)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string and return base64-encoded ciphertext."""
        if not plaintext:
            return ""

        encrypted_bytes = self.cipher.encrypt(plaintext.encode())
        return encrypted_bytes.decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64-encoded ciphertext and return plaintext."""
        if not ciphertext:
            return ""

        try:
            decrypted_bytes = self.cipher.decrypt(ciphertext.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_optional(self, plaintext: Optional[str]) -> Optional[str]:
        """Encrypt an optional string (handles None)."""
        return self.encrypt(plaintext) if plaintext else None

    def decrypt_optional(self, ciphertext: Optional[str]) -> Optional[str]:
        """Decrypt an optional string (handles None)."""
        return self.decrypt(ciphertext) if ciphertext else None


# Global instance
encryption_manager = EncryptionManager()
