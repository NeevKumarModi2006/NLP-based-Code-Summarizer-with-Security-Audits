import yaml
def parse_config(config_str):
    # VULNERABLE: Insecure YAML Deserialization
    return yaml.load(config_str)