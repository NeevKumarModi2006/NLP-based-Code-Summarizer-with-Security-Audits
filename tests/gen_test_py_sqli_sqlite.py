import sqlite3
def get_user(username):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # sql injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)