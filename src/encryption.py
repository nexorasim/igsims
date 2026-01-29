from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import logging

logger = logging.getLogger(__name__)

class DataEncryption:
    def __init__(self, password: str = None):
        if password:
            self.key = self._derive_key(password)
        else:
            self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        salt = b'igsim_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_or_generate_key(self) -> bytes:
        key_file = '.encryption_key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt(self, data: str) -> str:
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise

class SecureStorage:
    def __init__(self):
        self.encryption = DataEncryption()
    
    def store_api_key(self, service: str, api_key: str) -> str:
        encrypted_key = self.encryption.encrypt(api_key)
        return encrypted_key
    
    def retrieve_api_key(self, encrypted_key: str) -> str:
        return self.encryption.decrypt(encrypted_key)
    
    def store_sensitive_data(self, data: dict) -> dict:
        encrypted_data = {}
        for key, value in data.items():
            if isinstance(value, str) and ('key' in key.lower() or 'password' in key.lower() or 'secret' in key.lower()):
                encrypted_data[key] = self.encryption.encrypt(value)
            else:
                encrypted_data[key] = value
        return encrypted_data
    
    def retrieve_sensitive_data(self, encrypted_data: dict) -> dict:
        decrypted_data = {}
        for key, value in encrypted_data.items():
            if isinstance(value, str) and ('key' in key.lower() or 'password' in key.lower() or 'secret' in key.lower()):
                try:
                    decrypted_data[key] = self.encryption.decrypt(value)
                except:
                    decrypted_data[key] = value
            else:
                decrypted_data[key] = value
        return decrypted_data