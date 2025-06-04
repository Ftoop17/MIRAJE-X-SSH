# **MIRAJE-X: Ultimate Security & Caching Library**  
*(v3.0 | June 2024)*  


**The Most Advanced Python Security & Caching Solution**  

---

## 🔍 **Overview**  
**MIRAJE-X** is a next-generation Python library combining:  
✅ **Military-grade encryption** (AES-256, RSA, ChaCha20)  
✅ **Smart multi-layer caching** (Memory/Disk/Redis)  
✅ **Web security tools** (JWT, CSRF, Password Hashing)  
✅ **Framework integrations** (Flask, Django, FastAPI)  

Built by **The Temirbolatov** for developers who prioritize **security** and **performance**.  

---

## 🚀 **Quick Start**  

### Installation  
```bash
pip install mirage-x
# Optional dependencies:
pip install redis pymemcache argon2-cffi
```

### Basic Usage  
```python
from mirage_x import MirageX

# Initialize with default settings
mx = MirageX(secret_key="your_super_secret_key")

# Encrypt/Decrypt data
encrypted = mx.encrypt("Sensitive Data")
decrypted = mx.decrypt(encrypted)  

# Password hashing
hashed_pw = mx.hash_password("user123")
is_valid = mx.verify_password("user123", hashed_pw)

# Caching 
@mx.cached(ttl=300)  # Cache for 5 minutes
def expensive_operation(x):
    return x * x * x
```

---

## ✨ **Key Features**  

### 🔒 **Security Modules**  
| Feature          | Description                          |
|------------------|--------------------------------------|
| AES-256-GCM      | Authenticated encryption             |
| RSA-OAEP         | Asymmetric encryption (4096-bit)     |
| Argon2/Scrypt    | Password hashing algorithms          |
| JWT Tokens       | Secure token generation/validation   |
| CSRF Protection  | Built-in Flask middleware            |

### 🚄 **Caching System**  
```python
# Multi-backend support
mx = MirageX(
    cache_backend="redis"  # Options: memory/disk/redis/memcached
)

# Manual cache control
mx.cache_set("user:42", user_data, ttl=3600)
cached = mx.cache_get("user:42")
```

### 🛠 **Framework Integrations**  

#### Flask Example  
```python
from flask import Flask
app = Flask(__name__)

mx = MirageX()
mx.init_flask(app)  # Adds security middleware

@app.route("/secure")
def secure_route():
    token = mx.generate_jwt({"user_id": 42})
    return {"token": token}
```

---

## 📚 **Documentation**  

### Encryption Methods  
```python
# ChaCha20-Poly1305
encrypted = mx.encrypt(data, method="chacha20")

# RSA (Asymmetric)
public_key = mx.get_public_key()  # Share this
```

### Advanced Caching  
```python
# Disk cache compression
mx = MirageX(
    cache_backend="disk",
    compress=True  # Enable zlib compression
)
```

### Password Security  
```python
# Custom hashing parameters
mx = MirageX(
    password_algo="scrypt",  # argon2/scrypt/pbkdf2
    scrypt_params={"n": 2**18, "r": 8}
)
```

---

## ⚠️ **Security Best Practices**  
1. Always rotate `secret_key` every 6 months  
2. Use environment variables for sensitive data:  
   ```python
   import os
   mx = MirageX(os.getenv("SECRET_KEY"))
   ```
3. Enable HTTPS when transmitting encrypted data  

---

## 📜 **License**  
MIRAJE-X operates under **Custom License**:  
- Free for non-commercial use  
- Commercial license required for SaaS/products  
- [Full License Text](LICENSE.md)  

---

## 💬 **Support & Contact**  
Found a bug? Need help?  
📧 Email: support@mirage-x.com  
💬 Telegram: [@thetemirbolatov](https://t.me/thetemirbolatov)  

**Star us on GitHub!** ⭐  

---

```python
print("MIRAJE-X: Security Evolved")  # Happy coding!
```  

### 🔗 **Quick Links**  
- [API Reference](docs/API.md)  
- [Benchmarks](docs/BENCHMARKS.md)  
- [Release Notes](CHANGELOG.md)  



**© 2025 The Temirbolatov | MIRAJE-X**
