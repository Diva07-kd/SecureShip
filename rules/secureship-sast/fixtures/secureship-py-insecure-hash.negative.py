import hashlib

# Negative fixture: SHA-256 for secure hashing
def hash_user_password_safe(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Non-security hash usage (e.g. file checksum or bucket partitioning without security context)
def compute_data_bucket(data_bytes):
    return hashlib.md5(data_bytes).hexdigest()
