import os
def ping(host):
    # VULNERABLE: Command Injection
    os.system("ping " + host)