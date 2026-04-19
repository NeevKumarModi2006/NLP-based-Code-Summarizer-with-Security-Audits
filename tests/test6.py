
import subprocess
import os

def vulnerable_function():
    # Hardcoded API Key
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    # Command Injection
    user_input = input("Enter command: ")
    subprocess.Popen(user_input, shell=True) # Very Dangerous

    # Eval
    eval(user_input)

vulnerable_function()
