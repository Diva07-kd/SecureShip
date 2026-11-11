import hashlib

# Positive fixture: MD5/SHA1 used in password/token security context
def hash_user_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_auth_token_signature(token):
    session_signature = hashlib.sha1(token.encode()).hexdigest()
    return session_signature
