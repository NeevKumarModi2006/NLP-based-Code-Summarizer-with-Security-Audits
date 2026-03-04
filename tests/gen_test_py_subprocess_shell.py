import subprocess
def run_cmd(cmd):
    # command injection via shell
    subprocess.call(cmd, shell=True)