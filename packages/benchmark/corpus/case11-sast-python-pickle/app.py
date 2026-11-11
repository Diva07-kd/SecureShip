import pickle
def load_data(untrusted_stream):
    return pickle.loads(untrusted_stream)
