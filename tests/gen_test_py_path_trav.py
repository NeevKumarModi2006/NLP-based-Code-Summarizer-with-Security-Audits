def read_log(filename):
    # path traversal
    with open("/var/log/" + filename, 'r') as f:
        return f.read()