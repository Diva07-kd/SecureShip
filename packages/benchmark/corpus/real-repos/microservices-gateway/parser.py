import yaml

def safe_parse(raw_content):
    # safe_load is safe; vulnerable load / full_load is never called!
    return yaml.safe_load(raw_content)

print(safe_parse("service: gateway\nstatus: active"))
