# Negative fixture: parameterized database queries
def query_user_safe(cursor, username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

def query_user_by_id_safe(cursor, user_id):
    cursor.execute("SELECT * FROM accounts WHERE id = ?", (user_id,))
