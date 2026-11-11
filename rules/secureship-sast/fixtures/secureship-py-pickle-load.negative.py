import json

# Negative fixture: safe json serialization
def deserialize_user_safe(data):
    return json.loads(data)

def load_cache_safe(f):
    return json.load(f)
