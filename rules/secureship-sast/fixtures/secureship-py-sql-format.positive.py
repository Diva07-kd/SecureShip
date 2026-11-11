# Positive fixture: SQL queries built via string formatting or f-strings
def query_user_by_name(cursor, username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)

def query_user_by_id(cursor, user_id):
    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")
