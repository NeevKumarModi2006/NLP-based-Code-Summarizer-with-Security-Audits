import os
import subprocess
import sqlite3
import base64

# hardcoded secret
API_KEY = "sk-antigravity-1234567890abcdef1234567890abcdef"

def process_data(user_input):
    # command injection via shell=True
    subprocess.Popen(f"echo {user_input}", shell=True)

    # eval on user input
    result = eval(user_input)

    # sql injection via string format
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

    return result

if __name__ == "__main__":
    # user input source
    data = input("Enter your command: ")
    print(process_data(data))