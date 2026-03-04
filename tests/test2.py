import hashlib
import os

def hash_password(password: str):
    # hash with pbkdf2 and salt
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key

# safe user data
user_data = {"id": 1, "role": "user"}
print(f"User {user_data['id']} has been initialized.")