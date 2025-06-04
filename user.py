from mirage_x import MirageX, EncryptionMethod

# Initialize
mx = MirageX(secret_key="your_super_secret_key")

# Encrypt/Decrypt
encrypted = mx.encrypt("Top Secret", EncryptionMethod.AES)
decrypted = mx.decrypt(encrypted).decode()

# Password Hashing
hashed = mx.hash_password("user_password")
verified = mx.verify_password("user_password", hashed)

# Caching
@mx.cached(ttl=300)
def expensive_operation(x):
    return x * x

# JWT Tokens
token = mx.generate_jwt({"user_id": 42})
user_data = mx.verify_jwt(token)