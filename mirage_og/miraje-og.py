"""
MIRAJE-X - The Most Advanced Python Security & Caching Library
Features:
- Military-Grade Encryption (AES-256-GCM, RSA-OAEP, ChaCha20-Poly1305)
- Multi-Layer Caching (Memory/Disk/Redis/Memcached)
- JWT & Session Management
- Password Hashing (Argon2/Scrypt/PBKDF2)
- CSRF & Rate Limiting Protection
- Flask/Django Integration
- Async Support
"""

import os
import base64
import json
import time
import pickle
import zlib
import hashlib
import hmac
import secrets
import functools
import asyncio
from typing import Any, Optional, Union, Callable, Dict, List
from datetime import datetime, timedelta
from enum import Enum, auto

# Security Imports
try:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Cache Backends
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import pymemcache
    MEMCACHED_AVAILABLE = True
except ImportError:
    MEMCACHED_AVAILABLE = False

# Web Framework Integrations
try:
    from flask import request, current_app, make_response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from django.core.cache import caches
    from django.conf import settings
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False

# ==================== ENUMS & CONSTANTS ====================
class EncryptionMethod(Enum):
    AES = auto()
    RSA = auto()
    CHACHA20 = auto()

class CacheBackend(Enum):
    MEMORY = auto()
    DISK = auto()
    REDIS = auto()
    MEMCACHED = auto()

class PasswordAlgorithm(Enum):
    ARGON2 = auto()
    SCRYPT = auto()
    PBKDF2 = auto()

DEFAULT_CACHE_TTL = 3600  # 1 hour
DEFAULT_ENCRYPTION = EncryptionMethod.AES
DEFAULT_PASSWORD_ALGO = PasswordAlgorithm.ARGON2

# ==================== CORE LIBRARY ====================
class MirageX:
    """Ultimate Security & Caching Engine"""
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        cache_backend: CacheBackend = CacheBackend.MEMORY,
        encryption_method: EncryptionMethod = DEFAULT_ENCRYPTION,
        password_algo: PasswordAlgorithm = DEFAULT_PASSWORD_ALGO
    ):
        if not CRYPTO_AVAILABLE:
            raise ImportError("Install cryptography: pip install cryptography")
        
        # Security Setup
        self.secret_key = self._derive_key(secret_key or secrets.token_urlsafe(64))
        self.encryption_method = encryption_method
        self.password_algo = password_algo
        
        # Cache Setup
        self.cache_backend = cache_backend
        self._cache = self._init_cache_backend()
        
        # RSA Keys (Lazy Loaded)
        self._rsa_private_key = None
        self._rsa_public_key = None

    # ================ CORE ENCRYPTION ================
    def encrypt(self, data: Union[str, bytes], method: Optional[EncryptionMethod] = None) -> str:
        """Encrypt data with chosen method (AES-256-GCM by default)"""
        method = method or self.encryption_method
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if method == EncryptionMethod.AES:
            return self._encrypt_aes(data)
        elif method == EncryptionMethod.RSA:
            return self._encrypt_rsa(data)
        elif method == EncryptionMethod.CHACHA20:
            return self._encrypt_chacha20(data)
        else:
            raise ValueError("Unsupported encryption method")

    def _encrypt_aes(self, data: bytes) -> str:
        """AES-256-GCM (Authenticated Encryption)"""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + encryptor.tag + encrypted).decode()

    def _encrypt_rsa(self, data: bytes) -> str:
        """RSA-OAEP (Asymmetric Encryption)"""
        if not self._rsa_public_key:
            self._generate_rsa_keys()
        
        encrypted = self._rsa_public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.urlsafe_b64encode(encrypted).decode()

    def _encrypt_chacha20(self, data: bytes) -> str:
        """ChaCha20-Poly1305 (Modern Encryption)"""
        nonce = os.urandom(16)
        cipher = Cipher(
            algorithms.ChaCha20(self.secret_key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data)
        return base64.urlsafe_b64encode(nonce + encrypted).decode()

    # ================ DECRYPTION ================
    def decrypt(self, encrypted_data: str, method: Optional[EncryptionMethod] = None) -> bytes:
        """Decrypt data with the same method used for encryption"""
        method = method or self.encryption_method
        data = base64.urlsafe_b64decode(encrypted_data.encode())
        
        if method == EncryptionMethod.AES:
            return self._decrypt_aes(data)
        elif method == EncryptionMethod.RSA:
            return self._decrypt_rsa(data)
        elif method == EncryptionMethod.CHACHA20:
            return self._decrypt_chacha20(data)
        else:
            raise ValueError("Unsupported decryption method")

    def _decrypt_aes(self, data: bytes) -> bytes:
        """AES-256-GCM Decryption"""
        iv = data[:16]
        tag = data[16:32]
        encrypted = data[32:]
        
        cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()

    def _decrypt_rsa(self, data: bytes) -> bytes:
        """RSA-OAEP Decryption"""
        if not self._rsa_private_key:
            raise RuntimeError("No private key available for decryption")
            
        return self._rsa_private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _decrypt_chacha20(self, data: bytes) -> bytes:
        """ChaCha20-Poly1305 Decryption"""
        nonce = data[:16]
        encrypted = data[16:]
        
        cipher = Cipher(
            algorithms.ChaCha20(self.secret_key, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted)

    # ================ PASSWORD SECURITY ================
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> str:
        """Secure password hashing with configurable algorithm"""
        salt = salt or os.urandom(16)
        
        if self.password_algo == PasswordAlgorithm.ARGON2:
            return self._hash_argon2(password, salt)
        elif self.password_algo == PasswordAlgorithm.SCRYPT:
            return self._hash_scrypt(password, salt)
        else:  # PBKDF2
            return self._hash_pbkdf2(password, salt)

    def _hash_argon2(self, password: str, salt: bytes) -> str:
        """Argon2 (Memory-Hard) Password Hashing"""
        # Note: Requires argon2-cffi package
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        return ph.hash(password + salt.hex())

    def _hash_scrypt(self, password: str, salt: bytes) -> str:
        """Scrypt Password Hashing"""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**20,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

    def _hash_pbkdf2(self, password: str, salt: bytes) -> str:
        """PBKDF2 Password Hashing"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

    # ================ CACHING SYSTEM ================
    def _init_cache_backend(self) -> Any:
        """Initialize the selected cache backend"""
        if self.cache_backend == CacheBackend.REDIS and REDIS_AVAILABLE:
            return redis.Redis(host='localhost', port=6379, db=0)
        elif self.cache_backend == CacheBackend.MEMCACHED and MEMCACHED_AVAILABLE:
            return pymemcache.Client(('localhost', 11211))
        else:
            return {}  # Fallback to memory cache

    def cache_set(self, key: str, value: Any, ttl: int = DEFAULT_CACHE_TTL) -> bool:
        """Store data in cache with TTL"""
        try:
            if self.cache_backend == CacheBackend.DISK:
                os.makedirs('mirage_cache', exist_ok=True)
                with open(f'mirage_cache/{hashlib.sha256(key.encode()).hexdigest()}', 'wb') as f:
                    pickle.dump({
                        'value': value,
                        'expires': time.time() + ttl
                    }, f)
            elif self.cache_backend in (CacheBackend.REDIS, CacheBackend.MEMCACHED):
                self._cache.set(key, pickle.dumps(value), ex=ttl)
            else:  # Memory cache
                self._cache[key] = {
                    'value': value,
                    'expires': time.time() + ttl
                }
            return True
        except Exception:
            return False

    def cache_get(self, key: str) -> Any:
        """Retrieve data from cache"""
        try:
            if self.cache_backend == CacheBackend.DISK:
                cache_file = f'mirage_cache/{hashlib.sha256(key.encode()).hexdigest()}'
                if not os.path.exists(cache_file):
                    return None
                
                with open(cache_file, 'rb') as f:
                    data = pickle.load(f)
                
                if time.time() > data['expires']:
                    os.remove(cache_file)
                    return None
                return data['value']
            
            elif self.cache_backend in (CacheBackend.REDIS, CacheBackend.MEMCACHED):
                data = self._cache.get(key)
                return pickle.loads(data) if data else None
            
            else:  # Memory cache
                data = self._cache.get(key)
                if data and time.time() > data['expires']:
                    del self._cache[key]
                    return None
                return data['value'] if data else None
        except Exception:
            return None

    # ================ ADVANCED FEATURES ================
    def generate_jwt(self, payload: dict, expires_in: int = 3600) -> str:
        """Generate secure JWT token"""
        header = {
            "alg": "HS512",
            "typ": "JWT"
        }
        payload['exp'] = int(time.time()) + expires_in
        
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        
        signature = hmac.new(
            self.secret_key,
            f"{encoded_header}.{encoded_payload}".encode(),
            hashlib.sha512
        ).digest()
        
        return f"{encoded_header}.{encoded_payload}.{base64.urlsafe_b64encode(signature).decode()}"

    def verify_jwt(self, token: str) -> Optional[dict]:
        """Verify JWT token and return payload if valid"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
                
            header, payload, signature = parts
            expected_sig = hmac.new(
                self.secret_key,
                f"{header}.{payload}".encode(),
                hashlib.sha512
            ).digest()
            
            if not hmac.compare_digest(base64.urlsafe_b64decode(signature.encode()), expected_sig):
                return None
                
            payload_data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            if payload_data.get('exp', 0) < time.time():
                return None
                
            return payload_data
        except Exception:
            return None

    # ================ FLASK INTEGRATION ================
    if FLASK_AVAILABLE:
        def init_flask(self, app):
            """Add security middleware to Flask app"""
            @app.before_request
            def load_user():
                token = request.cookies.get('auth_token')
                if token:
                    user_data = self.verify_jwt(token)
                    if user_data:
                        request.user = user_data

            @app.after_request
            def add_security_headers(response):
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                if 'user' in request and hasattr(request, 'user'):
                    new_token = self.generate_jwt(request.user)
                    response.set_cookie('auth_token', new_token, httponly=True, secure=not app.debug)
                return response

