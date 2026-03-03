import hashlib
import os

def hash_password(password: str):
    """Securely hashes a password using a random salt and PBKDF2."""
    salt = os.urandom(16)
    # Using a strong, modern hashing algorithm
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key

# Example of safe internal logic
user_data = {"id": 1, "role": "user"}
print(f"User {user_data['id']} has been initialized.")