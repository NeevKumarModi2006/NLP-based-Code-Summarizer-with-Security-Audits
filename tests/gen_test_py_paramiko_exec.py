import paramiko
def run_ssh(cmd):
    client = paramiko.SSHClient()
    # VULNERABLE: Command Injection
    client.exec_command(cmd)