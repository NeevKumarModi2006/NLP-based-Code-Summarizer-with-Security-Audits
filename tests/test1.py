import os
import subprocess
import sqlite3
import base64

# 1. Hardcoded Secret (Test for Scanner)
API_KEY = "sk-antigravity-1234567890abcdef1234567890abcdef"

def process_data(user_input):
    # 2. Command Injection (Test for AST Sinks & Scanner)
    # The tool should flag Popen with shell=True as CRITICAL
    subprocess.Popen(f"echo {user_input}", shell=True)

    # 3. Dynamic Execution (Test for AST Sinks)
    # Using eval on user input is a massive risk
    result = eval(user_input)
    
    # 4. SQL Injection (Test for Scanner)
    # string formatting in queries should be flagged
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    return result

if __name__ == "__main__":
    # 5. User Input Source (Test for AST Sources)
    data = input("Enter your command: ")
    print(process_data(data))