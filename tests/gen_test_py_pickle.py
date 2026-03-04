import pickle
def load_data(data):
    # unsafe deserialization
    return pickle.loads(data)