import pickle

# Positive fixture: unsafe pickle deserialization
def deserialize_user(data):
    return pickle.loads(data)

def load_cache(f):
    return pickle.load(f)
