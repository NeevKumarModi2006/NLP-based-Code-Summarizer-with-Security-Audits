
def get_user_data(user_id):
    import sqlite3
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # VULNERABLE: F-string injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # VULNERABLE: Format string injection
    query2 = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(query2)
    
    # VULNERABLE: Percentage formatting
    query3 = "SELECT * FROM users WHERE id = %s" % (user_id)
    cursor.execute(query3)

get_user_data("1 OR 1=1")
