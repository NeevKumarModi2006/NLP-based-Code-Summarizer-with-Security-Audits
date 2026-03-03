import hashlib
def hash_pass(password):
    # VULNERABLE: Weak Hash
    return hashlib.md5(password.encode()).hexdigest()