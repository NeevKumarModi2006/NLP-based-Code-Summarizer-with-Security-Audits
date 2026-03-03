import os
import subprocess

AWS_SECRET = "AKIAIMORKEITH4EXAMPLE"

def run_system_check(command_suffix):
    cmd = "echo status: " + command_suffix
    subprocess.Popen(cmd, shell=True)

user_val = input("Enter diagnostic flag: ")
run_system_check(user_val)