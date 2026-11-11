import yaml

# Negative fixture: safe yaml loading
def load_config_safe(stream):
    return yaml.safe_load(stream)

def load_data_safe(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)
