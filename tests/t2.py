import hashlib

def weak_hash(data):
    # LOW RISK: MD5 is cryptographically broken/weak
    return hashlib.md5(data.encode()).hexdigest()

# INFO: Hardcoded configuration (not a secret, but bad practice)
DEBUG_MODE = True
temp_dir = "/tmp/my_app_logs"