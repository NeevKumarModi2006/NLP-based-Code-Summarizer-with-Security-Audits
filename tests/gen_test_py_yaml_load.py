import yaml
def parse_config(config_str):
    # unsafe yaml deserialization
    return yaml.load(config_str)