import hashlib
import os

def secure_password_store(password: str):
    # hash password with pbkdf2 and random salt
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key

# safe logic
print("System initialized successfully.")