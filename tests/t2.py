import hashlib

def weak_hash(data):
    # md5 is weak
    return hashlib.md5(data.encode()).hexdigest()

# hardcoded config
DEBUG_MODE = True
temp_dir = "/tmp/my_app_logs"