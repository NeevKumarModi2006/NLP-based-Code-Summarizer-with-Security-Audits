import paramiko
def run_ssh(cmd):
    client = paramiko.SSHClient()
    # command injection via ssh
    client.exec_command(cmd)