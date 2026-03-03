def read_log(filename):
    # VULNERABLE: Path Traversal
    with open("/var/log/" + filename, 'r') as f:
        return f.read()