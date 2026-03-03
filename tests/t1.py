import hashlib
import os

def secure_password_store(password: str):
    """Uses industry-standard PBKDF2 with a random salt."""
    salt = os.urandom(16)
    # Securely hash with 100,000 iterations
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key

# Standard safe logic
print("System initialized successfully.")