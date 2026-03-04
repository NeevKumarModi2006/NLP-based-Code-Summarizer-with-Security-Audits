import hashlib
def hash_pass(password):
    # weak hash
    return hashlib.md5(password.encode()).hexdigest()