import yaml

# Positive fixture: unsafe yaml.load
def load_config(stream):
    return yaml.load(stream, Loader=yaml.Loader)

def load_data(raw):
    return yaml.unsafe_load(raw)
