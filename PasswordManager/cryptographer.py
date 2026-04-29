"""Cryptographic operations for Password Manager
   Handles encryption, decryption, and key derivation"""

import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from config import settings
from database import db_manager

class CryptoManager:
    """Manages cryptographic operations"""
    
    def __init__(self):
        self.key = None
        self.salt = None
        self.fernet = None
    
    def create_master_password(self, password: str) -> bool:
        """Create master password with PBKDF2 key derivation"""
        if len(password) < settings.get_min_master_password_length():
            print(f"Master password must be at least {settings.get_min_master_password_length()} characters long.")
            return False
        
        # Generate salt and derive key
        self.salt = secrets.token_bytes(settings.get_salt_length())
        self.key = self.derive_key_from_password(password, self.salt)
        
        # Store salt in database
        db_manager.store_salt(self.salt)
        
        # Initialize Fernet
        self.fernet = Fernet(self.key)
        
        return True
    
    def load_master_password(self, password: str) -> bool:
        """Load and verify master password"""
        # Get salt from database
        self.salt = db_manager.get_salt()
        if not self.salt:
            print("No master password found. Please create one first.")
            return False
        
        # Derive key from password
        self.key = self.derive_key_from_password(password, self.salt)
        
        # Test the key by trying to encrypt/decrypt
        try:
            test_fernet = Fernet(self.key)
            test_data = test_fernet.encrypt(b"test")
            test_fernet.decrypt(test_data)
            
            # If successful, initialize Fernet
            self.fernet = test_fernet
            return True
        except Exception:
            print("Incorrect master password.")
            return False
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=settings.get_pbkdf2_iterations(),
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_password(self, password: str) -> str:
        """Encrypt a password"""
        if not self.fernet:
            raise ValueError("No encryption key available")
        return self.fernet.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt a password"""
        if not self.fernet:
            raise ValueError("No encryption key available")
        return self.fernet.decrypt(encrypted_password.encode()).decode()
    
    def is_key_loaded(self) -> bool:
        """Check if encryption key is loaded"""
        return self.key is not None and self.fernet is not None
    
    def clear_key(self):
        """Clear the encryption key from memory"""
        self.key = None
        self.salt = None
        self.fernet = None

# Global crypto manager instance
crypto_manager = CryptoManager()
