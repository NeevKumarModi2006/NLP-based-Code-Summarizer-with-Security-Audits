import os
def ping(host):
    # command injection
    os.system("ping " + host)