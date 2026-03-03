import subprocess
def run_cmd(cmd):
    # VULNERABLE: Command Injection
    subprocess.call(cmd, shell=True)