import pickle
def load_data(data):
    # VULNERABLE: Insecure Deserialization
    return pickle.loads(data)